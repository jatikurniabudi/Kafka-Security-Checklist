"""
Pengecekan yang dilakukan lewat Kafka AdminClient (kafka-python).
Ini adalah pengecekan "remote" - tidak butuh akses SSH ke broker.

Catatan penting: DescribeConfigs untuk resource BROKER membutuhkan izin
DESCRIBE_CONFIGS pada cluster. Jika user/credential yang dipakai tool ini
tidak punya izin tersebut, sebagian cek akan berstatus ERROR/SKIP - itu
mengindikasikan permission tool ini sendiri terlalu sempit, bukan berarti
brokernya aman.
"""

from kafka import KafkaAdminClient
from kafka.admin import ConfigResource, ConfigResourceType, ACLFilter, ACLOperation, ACLPermissionType, ResourcePattern, ResourceType, ACLResourcePatternType
from kafka.errors import KafkaError

from .models import CheckResult, Status
from .config import AuditConfig


def _build_admin_client(cfg: AuditConfig) -> KafkaAdminClient:
    kwargs = dict(
        bootstrap_servers=cfg.bootstrap_servers,
        security_protocol=cfg.security_protocol,
        client_id="kafka-security-audit",
        request_timeout_ms=15000,
    )
    if cfg.security_protocol in ("SASL_PLAINTEXT", "SASL_SSL"):
        kwargs.update(
            sasl_mechanism=cfg.sasl_mechanism,
            sasl_plain_username=cfg.sasl_username,
            sasl_plain_password=cfg.sasl_password,
        )
    if cfg.security_protocol in ("SSL", "SASL_SSL"):
        kwargs.update(
            ssl_cafile=cfg.ssl_cafile,
            ssl_certfile=cfg.ssl_certfile,
            ssl_keyfile=cfg.ssl_keyfile,
            ssl_check_hostname=cfg.ssl_check_hostname,
        )
    return KafkaAdminClient(**kwargs)


def _get_broker_configs(admin: KafkaAdminClient):
    """Ambil config dari semua broker, kembalikan dict broker_id -> {key: value}."""
    cluster = admin.describe_cluster() if hasattr(admin, "describe_cluster") else None
    broker_ids = []
    try:
        metadata = admin._client.cluster
        broker_ids = [b.nodeId for b in metadata.brokers()]
    except Exception:
        pass

    results = {}
    for bid in broker_ids:
        try:
            resource = ConfigResource(ConfigResourceType.BROKER, str(bid))
            configs = admin.describe_configs([resource])
            # kafka-python mengembalikan list of DescribeConfigsResponse
            for resp in configs:
                for resource_result in resp.resources:
                    # resource_result: error_code, error_message, resource_type, resource_name, config_entries
                    entries = resource_result[4]
                    parsed = {e[0]: e[1] for e in entries}  # name -> value
                    results[bid] = parsed
        except Exception as e:
            results[bid] = {"__error__": str(e)}
    return results


def check_authentication(cfg: AuditConfig, admin: KafkaAdminClient) -> list:
    out = []

    # 1.1 SASL/mTLS untuk client-broker
    proto = cfg.security_protocol.upper()
    if proto in ("SASL_SSL", "SSL"):
        out.append(CheckResult("1.1", "Authentication",
                                "SASL/mTLS aktif untuk client-broker",
                                Status.PASS, f"Listener client menggunakan {proto}"))
    elif proto == "SASL_PLAINTEXT":
        out.append(CheckResult("1.1", "Authentication",
                                "SASL/mTLS aktif untuk client-broker",
                                Status.WARN,
                                "SASL aktif tapi tanpa TLS (SASL_PLAINTEXT) - kredensial masih bisa disadap.",
                                "Ganti ke SASL_SSL agar autentikasi dan transport sama-sama terenkripsi."))
    else:
        out.append(CheckResult("1.1", "Authentication",
                                "SASL/mTLS aktif untuk client-broker",
                                Status.FAIL,
                                f"Koneksi tool ini menggunakan {proto} (tanpa autentikasi).",
                                "Aktifkan SASL_SSL atau mTLS untuk listener client."))

    # 1.5 PLAIN tanpa TLS
    if proto == "SASL_PLAINTEXT" and (cfg.sasl_mechanism or "").upper() == "PLAIN":
        out.append(CheckResult("1.5", "Authentication",
                                "Mekanisme PLAIN tidak dipakai tanpa TLS",
                                Status.FAIL,
                                "SASL/PLAIN dipakai di atas PLAINTEXT - password dikirim base64 tanpa enkripsi.",
                                "Gunakan SCRAM-SHA-256/512 dan/atau bungkus dengan TLS."))
    else:
        out.append(CheckResult("1.5", "Authentication",
                                "Mekanisme PLAIN tidak dipakai tanpa TLS",
                                Status.PASS if proto != "PLAINTEXT" else Status.SKIP,
                                "Tidak terdeteksi SASL/PLAIN di atas PLAINTEXT dari sisi koneksi tool ini."))

    # 1.2 Inter-broker protocol - butuh describe broker config
    broker_configs = _get_broker_configs(admin)
    if not broker_configs:
        out.append(CheckResult("1.2", "Authentication",
                                "Autentikasi antar-broker bukan PLAINTEXT",
                                Status.ERROR,
                                "Tidak bisa mengambil config broker (cek permission DESCRIBE_CONFIGS)."))
    else:
        any_plain = False
        details = []
        for bid, conf in broker_configs.items():
            if "__error__" in conf:
                details.append(f"broker {bid}: error - {conf['__error__']}")
                continue
            inter_proto = conf.get("security.inter.broker.protocol") or conf.get("inter.broker.listener.name", "")
            details.append(f"broker {bid}: {inter_proto or 'tidak diketahui'}")
            if inter_proto and "PLAINTEXT" == inter_proto.upper():
                any_plain = True
        if any_plain:
            out.append(CheckResult("1.2", "Authentication",
                                    "Autentikasi antar-broker bukan PLAINTEXT",
                                    Status.FAIL, "; ".join(details),
                                    "Set security.inter.broker.protocol ke SASL_SSL/SSL."))
        elif details:
            out.append(CheckResult("1.2", "Authentication",
                                    "Autentikasi antar-broker bukan PLAINTEXT",
                                    Status.PASS, "; ".join(details)))
        else:
            out.append(CheckResult("1.2", "Authentication",
                                    "Autentikasi antar-broker bukan PLAINTEXT",
                                    Status.MANUAL, "Tidak ditemukan info inter-broker protocol yang jelas."))

    # 1.3 Autentikasi ZK/KRaft controller terpisah -> lihat modul zk_checks
    out.append(CheckResult("1.3", "Authentication",
                            "Autentikasi ZooKeeper/KRaft controller terpisah",
                            Status.MANUAL,
                            "Dicek lebih lanjut oleh modul zk_checks jika zookeeper_hosts diisi di config.",
                            "Lihat hasil kategori 'ZooKeeper/KRaft'."))

    # 1.4 Rotasi kredensial - tidak bisa diverifikasi otomatis
    out.append(CheckResult("1.4", "Authentication",
                            "Rotasi credential/password dilakukan berkala",
                            Status.MANUAL,
                            "Butuh review proses operasional/IAM, tidak bisa dicek dari Kafka API.",
                            "Pastikan ada kebijakan rotasi (misal via secret manager) dan dicatat kapan terakhir diputar."))

    return out


def check_encryption_config(cfg: AuditConfig, admin: KafkaAdminClient) -> list:
    """Bagian yang bisa dicek dari broker config saja (selebihnya di tls_checks.py)."""
    out = []
    broker_configs = _get_broker_configs(admin)

    client_auth_values = []
    for bid, conf in broker_configs.items():
        if "__error__" in conf:
            continue
        v = conf.get("ssl.client.auth")
        if v:
            client_auth_values.append((bid, v))

    if not broker_configs or all("__error__" in c for c in broker_configs.values()):
        out.append(CheckResult("2.3", "Encryption",
                                "ssl.client.auth=required (mTLS) jika diperlukan",
                                Status.ERROR, "Tidak bisa mengambil config broker."))
    elif client_auth_values:
        not_required = [b for b, v in client_auth_values if v.lower() != "required"]
        if not_required:
            out.append(CheckResult("2.3", "Encryption",
                                    "ssl.client.auth=required (mTLS) jika diperlukan",
                                    Status.WARN,
                                    f"Broker berikut belum 'required': {not_required}",
                                    "Set ssl.client.auth=required jika ingin mTLS wajib."))
        else:
            out.append(CheckResult("2.3", "Encryption",
                                    "ssl.client.auth=required (mTLS) jika diperlukan",
                                    Status.PASS, f"Semua broker: {client_auth_values}"))
    else:
        out.append(CheckResult("2.3", "Encryption",
                                "ssl.client.auth=required (mTLS) jika diperlukan",
                                Status.MANUAL,
                                "ssl.client.auth tidak diset - mTLS mungkin tidak dipakai (opsional tergantung kebutuhan)."))

    # 2.5 Disk encryption at rest - tidak bisa dicek dari Admin API
    out.append(CheckResult("2.5", "Encryption",
                            "Data at-rest di disk broker terenkripsi",
                            Status.MANUAL,
                            "Perlu cek langsung di level OS/disk/cloud provider (LUKS, EBS encryption, dll).",
                            "Gunakan modul ssh_checks atau cek konsol cloud provider."))
    return out


def check_authorization(cfg: AuditConfig, admin: KafkaAdminClient) -> list:
    out = []
    broker_configs = _get_broker_configs(admin)

    authorizer_values = []
    allow_everyone_values = []
    for bid, conf in broker_configs.items():
        if "__error__" in conf:
            continue
        az = conf.get("authorizer.class.name")
        if az is not None:
            authorizer_values.append((bid, az))
        ae = conf.get("allow.everyone.if.no.acl.found")
        if ae is not None:
            allow_everyone_values.append((bid, ae))

    # 3.1 ACL authorizer aktif
    if not broker_configs:
        out.append(CheckResult("3.1", "Authorization", "ACL authorizer aktif", Status.ERROR,
                                "Tidak bisa mengambil config broker."))
    elif authorizer_values:
        empty = [b for b, v in authorizer_values if not v]
        if empty:
            out.append(CheckResult("3.1", "Authorization", "ACL authorizer aktif", Status.FAIL,
                                    f"Broker tanpa authorizer.class.name: {empty}",
                                    "Set authorizer.class.name ke AclAuthorizer atau StandardAuthorizer (KRaft)."))
        else:
            out.append(CheckResult("3.1", "Authorization", "ACL authorizer aktif", Status.PASS,
                                    f"{authorizer_values}"))
    else:
        out.append(CheckResult("3.1", "Authorization", "ACL authorizer aktif", Status.FAIL,
                                "authorizer.class.name tidak diset di broker manapun.",
                                "Aktifkan AclAuthorizer/StandardAuthorizer."))

    # 3.3 Deny by default
    if allow_everyone_values:
        bad = [b for b, v in allow_everyone_values if str(v).lower() == "true"]
        if bad:
            out.append(CheckResult("3.3", "Authorization", "Deny by default (allow.everyone.if.no.acl.found=false)",
                                    Status.FAIL, f"Broker dengan allow.everyone=true: {bad}",
                                    "Set allow.everyone.if.no.acl.found=false."))
        else:
            out.append(CheckResult("3.3", "Authorization", "Deny by default (allow.everyone.if.no.acl.found=false)",
                                    Status.PASS, f"{allow_everyone_values}"))
    else:
        out.append(CheckResult("3.3", "Authorization", "Deny by default (allow.everyone.if.no.acl.found=false)",
                                Status.MANUAL, "Nilai tidak diset eksplisit; default Kafka adalah false, tapi perlu diverifikasi."))

    # 3.2 Least privilege - lihat ACL yang terlalu terbuka
    try:
        acl_filter = ACLFilter(
            principal=None, host=None,
            operation=ACLOperation.ANY,
            permission_type=ACLPermissionType.ANY,
            resource_pattern=ResourcePattern(ResourceType.ANY, "*", ACLResourcePatternType.ANY),
        )
        acls = admin.describe_acls(acl_filter)
        acl_list = list(acls) if acls else []
        risky = []
        for a in acl_list:
            # struktur bervariasi antar versi kafka-python; ambil representasi string
            s = str(a)
            if "*" in s and "ALLOW" in s.upper():
                risky.append(s)
        if risky:
            out.append(CheckResult("3.2", "Authorization", "ACL mengikuti least privilege",
                                    Status.WARN, f"Ditemukan {len(risky)} ACL wildcard ALLOW, contoh: {risky[:3]}",
                                    "Tinjau ACL wildcard (topic='*' atau principal='*') dan persempit scope-nya."))
        else:
            out.append(CheckResult("3.2", "Authorization", "ACL mengikuti least privilege",
                                    Status.PASS, f"Total ACL ditemukan: {len(acl_list)}, tidak ada wildcard ALLOW yang jelas."))
    except Exception as e:
        out.append(CheckResult("3.2", "Authorization", "ACL mengikuti least privilege",
                                Status.ERROR, f"Gagal describe ACL: {e}",
                                "Pastikan credential tool ini punya izin DESCRIBE pada resource CLUSTER."))

    # 3.4 & 3.5 manual
    out.append(CheckResult("3.4", "Authorization", "Pemisahan izin per environment/tim",
                            Status.MANUAL, "Perlu review konvensi penamaan topic & mapping principal per tim/environment."))
    out.append(CheckResult("3.5", "Authorization", "Audit ACL berkala, hapus yang tidak terpakai",
                            Status.MANUAL, "Jadwalkan review ACL berkala; tool ini hanya snapshot kondisi saat ini."))

    return out


def check_broker_hardening(cfg: AuditConfig, admin: KafkaAdminClient) -> list:
    out = []
    broker_configs = _get_broker_configs(admin)

    def get_all(key):
        vals = []
        for bid, conf in broker_configs.items():
            if "__error__" in conf:
                continue
            if key in conf:
                vals.append((bid, conf[key]))
        return vals

    checks_map = [
        ("6.1", "auto.create.topics.enable", "false", "auto.create.topics.enable dinonaktifkan",
         "Set auto.create.topics.enable=false untuk mencegah topic liar dibuat otomatis."),
        ("6.3", "unclean.leader.election.enable", "false", "unclean.leader.election.enable dinonaktifkan",
         "Set unclean.leader.election.enable=false untuk mencegah potensi data loss."),
    ]

    for check_id, key, expected, title, rec in checks_map:
        vals = get_all(key)
        if not vals:
            out.append(CheckResult(check_id, "Broker Hardening", title, Status.MANUAL,
                                    f"Config '{key}' tidak ditemukan secara eksplisit (mungkin default).", rec))
            continue
        bad = [b for b, v in vals if str(v).lower() != expected]
        if bad:
            out.append(CheckResult(check_id, "Broker Hardening", title, Status.FAIL,
                                    f"Broker dengan {key}!={expected}: {bad}", rec))
        else:
            out.append(CheckResult(check_id, "Broker Hardening", title, Status.PASS, f"{vals}"))

    # 6.2 delete.topic.enable - bukan pass/fail mutlak, tergantung kombinasi dengan ACL
    vals = get_all("delete.topic.enable")
    if vals:
        out.append(CheckResult("6.2", "Broker Hardening",
                                "delete.topic.enable dikombinasikan dengan ACL yang ketat",
                                Status.WARN if any(str(v).lower() == "true" for _, v in vals) else Status.PASS,
                                f"{vals}",
                                "Jika true, pastikan hanya principal admin tertentu yang punya izin DELETE pada topic."))
    else:
        out.append(CheckResult("6.2", "Broker Hardening",
                                "delete.topic.enable dikombinasikan dengan ACL yang ketat",
                                Status.MANUAL, "Config tidak ditemukan eksplisit."))

    # 6.4 non-root - tidak bisa dicek tanpa SSH
    out.append(CheckResult("6.4", "Broker Hardening", "Broker dijalankan dengan user non-root",
                            Status.SKIP, "Butuh akses SSH ke host broker (lihat ssh_checks).",
                            "Jalankan modul ssh_checks dengan target broker diisi."))

    # 6.5 quotas
    try:
        quotas = admin.describe_client_quotas() if hasattr(admin, "describe_client_quotas") else None
        if quotas:
            out.append(CheckResult("6.5", "Broker Hardening", "Resource quota producer/consumer diterapkan",
                                    Status.PASS, f"Ditemukan {len(quotas)} entri quota."))
        else:
            out.append(CheckResult("6.5", "Broker Hardening", "Resource quota producer/consumer diterapkan",
                                    Status.WARN, "Tidak ditemukan quota terkonfigurasi.",
                                    "Pertimbangkan quota.producer.default/quota.consumer.default untuk mencegah abuse."))
    except Exception as e:
        out.append(CheckResult("6.5", "Broker Hardening", "Resource quota producer/consumer diterapkan",
                                Status.ERROR, f"API describe_client_quotas tidak tersedia atau gagal: {e}"))

    # 6.6 JMX remote - butuh SSH/portscan, tandai manual
    out.append(CheckResult("6.6", "Broker Hardening", "JMX remote tanpa autentikasi dinonaktifkan",
                            Status.MANUAL, "Perlu cek JAVA_OPTS/JMX config di startup script broker (lihat ssh_checks).",
                            "Pastikan com.sun.management.jmxremote.authenticate=true jika JMX remote diaktifkan."))

    return out


def check_network(cfg: AuditConfig, admin: KafkaAdminClient) -> list:
    out = []
    try:
        metadata = admin._client.cluster
        listeners_seen = set()
        for b in metadata.brokers():
            listeners_seen.add((b.host, b.port))
        out.append(CheckResult("4.3", "Network", "Listener internal vs eksternal terpisah",
                                Status.MANUAL,
                                f"Tool ini melihat {len(listeners_seen)} endpoint broker dari sisi client: {list(listeners_seen)[:5]}. "
                                "Untuk memastikan pemisahan internal/eksternal, bandingkan dengan listener.security.protocol.map di server.properties.",
                                "Gunakan ssh_checks untuk membaca server.properties langsung."))
    except Exception as e:
        out.append(CheckResult("4.3", "Network", "Listener internal vs eksternal terpisah",
                                Status.ERROR, f"Gagal membaca metadata broker: {e}"))

    for cid, title in [
        ("4.1", "Cluster berada di private network/VPC"),
        ("4.2", "Firewall/security group membatasi akses"),
        ("4.4", "Akses admin lewat VPN/bastion host"),
    ]:
        out.append(CheckResult(cid, "Network", title, Status.MANUAL,
                                "Tidak bisa diverifikasi dari Kafka API - perlu cek konfigurasi cloud/network provider.",
                                "Cross-check dengan security group/VPC config di cloud console atau firewall rules."))
    return out


def check_kraft_or_zk(cfg: AuditConfig, admin: KafkaAdminClient) -> list:
    out = []
    broker_configs = _get_broker_configs(admin)
    process_roles_found = False
    for bid, conf in broker_configs.items():
        if "__error__" in conf:
            continue
        if conf.get("process.roles"):
            process_roles_found = True

    if process_roles_found:
        out.append(CheckResult("5.2", "ZooKeeper/KRaft", "Mode cluster (KRaft vs ZooKeeper)",
                                Status.PASS, "Terdeteksi 'process.roles' -> cluster berjalan dalam mode KRaft (tanpa ZooKeeper)."))
        out.append(CheckResult("5.1", "ZooKeeper/KRaft", "ZooKeeper SASL+ACL aktif",
                                Status.SKIP, "Cluster memakai KRaft, item ZooKeeper tidak relevan."))
        out.append(CheckResult("5.3", "ZooKeeper/KRaft", "Port ZooKeeper (2181) dibatasi",
                                Status.SKIP, "Cluster memakai KRaft, tidak ada ZooKeeper."))
    else:
        out.append(CheckResult("5.2", "ZooKeeper/KRaft", "Mode cluster (KRaft vs ZooKeeper)",
                                Status.WARN if not cfg.zookeeper_hosts else Status.MANUAL,
                                "Tidak terdeteksi 'process.roles' -> kemungkinan masih memakai ZooKeeper.",
                                "Pertimbangkan migrasi ke KRaft untuk mengurangi attack surface."))
        if cfg.zookeeper_hosts:
            out.append(CheckResult("5.1", "ZooKeeper/KRaft", "ZooKeeper SASL+ACL aktif",
                                    Status.MANUAL, "Dicek lebih lanjut oleh modul zk_checks (butuh library kazoo).",
                                    "Jalankan zk_checks.check_zookeeper() untuk hasil detail."))
        else:
            out.append(CheckResult("5.1", "ZooKeeper/KRaft", "ZooKeeper SASL+ACL aktif",
                                    Status.SKIP, "zookeeper_hosts tidak diisi di config."))
        out.append(CheckResult("5.3", "ZooKeeper/KRaft", "Port ZooKeeper (2181) dibatasi",
                                Status.MANUAL, "Perlu port scan/firewall review dari luar cluster."))
    return out


def check_patch_version(cfg: AuditConfig, admin: KafkaAdminClient) -> list:
    from .patch_checks import check_kafka_version
    return check_kafka_version(cfg, admin)


def run_all_admin_checks(cfg: AuditConfig) -> list:
    results = []
    try:
        admin = _build_admin_client(cfg)
    except Exception as e:
        results.append(CheckResult("0.0", "Connection", "Berhasil terhubung ke cluster",
                                    Status.ERROR, f"Gagal membuat AdminClient: {e}"))
        return results

    try:
        results += check_authentication(cfg, admin)
        results += check_encryption_config(cfg, admin)
        results += check_authorization(cfg, admin)
        results += check_broker_hardening(cfg, admin)
        results += check_network(cfg, admin)
        results += check_kraft_or_zk(cfg, admin)
        results += check_patch_version(cfg, admin)
    finally:
        try:
            admin.close()
        except Exception:
            pass

    return results
