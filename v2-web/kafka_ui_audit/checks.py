"""
Logic pemetaan response kafka-ui API ke item checklist keamanan Kafka.
Sumber data SEMUA lewat REST API dashboard (bukan native Kafka protocol),
jadi setiap CheckResult diberi catatan "sumber: dashboard API" di detail-nya
supaya tidak disalahartikan setara dengan hasil DescribeConfigs langsung ke broker.
"""

from .models import CheckResult, Status


def _parse_listeners(listeners_value: str):
    """'SASL_SSL://0.0.0.0:9093,PLAINTEXT://0.0.0.0:9092' -> ['SASL_SSL', 'PLAINTEXT']"""
    if not listeners_value:
        return []
    protocols = []
    for entry in listeners_value.split(","):
        entry = entry.strip()
        if "://" in entry:
            protocols.append(entry.split("://")[0].strip())
    return protocols


def _resolve_inter_broker_protocol(conf: dict):
    """Tentukan protokol inter-broker dari kombinasi config yang mungkin ada."""
    direct = conf.get("security.inter.broker.protocol")
    if direct:
        return direct

    listener_name = conf.get("inter.broker.listener.name")
    proto_map = conf.get("listener.security.protocol.map")
    if listener_name and proto_map:
        for entry in proto_map.split(","):
            entry = entry.strip()
            if ":" in entry:
                name, proto = entry.split(":", 1)
                if name.strip().upper() == listener_name.strip().upper():
                    return proto.strip()
    return None


def check_patch_version(client) -> list:
    out = []
    clusters, err = client.get_clusters()
    version = None
    if err:
        out.append(CheckResult("10.1", "Patch Management", "Kafka berjalan di versi yang masih didukung",
                                Status.ERROR, f"[sumber: dashboard API] Gagal ambil /api/clusters: {err}"))
    else:
        match = next((c for c in clusters if c.get("name") == client.cluster_name), None)
        if match and match.get("version"):
            version = match["version"]

        if not version:
            stats, serr = client.get_cluster_stats()
            if not serr and stats:
                version = stats.get("version")

        if version:
            out.append(CheckResult("10.1", "Patch Management", "Kafka berjalan di versi yang masih didukung",
                                    Status.MANUAL,
                                    f"[sumber: dashboard API] Terdeteksi versi Kafka: {version}. "
                                    "Cross-check manual ke NVD/mailing list Kafka security untuk CVE versi ini.",
                                    "Bandingkan versi ini dengan advisory keamanan terbaru."))
        else:
            out.append(CheckResult("10.1", "Patch Management", "Kafka berjalan di versi yang masih didukung",
                                    Status.MANUAL, "[sumber: dashboard API] Field versi tidak ditemukan di response."))
    return out


def check_authentication_and_encryption(broker_configs: dict) -> list:
    out = []
    valid = {bid: c for bid, c in broker_configs.items() if "__error__" not in c}

    if not valid:
        for cid, title in [("1.1", "SASL/mTLS aktif untuk client-broker"),
                            ("1.2", "Autentikasi antar-broker bukan PLAINTEXT"),
                            ("1.5", "Mekanisme PLAIN tidak dipakai tanpa TLS"),
                            ("2.1", "TLS aktif di listener client")]:
            out.append(CheckResult(cid, "Authentication/Encryption", title, Status.ERROR,
                                    "[sumber: dashboard API] Tidak ada config broker yang berhasil diambil "
                                    "(cek permission user dashboard: apakah dia boleh lihat broker config?)."))
        return out

    # 1.1 & 2.1 & 1.5 - dari string 'listeners'
    all_protocols = set()
    plaintext_hosts = []
    for bid, conf in valid.items():
        listeners = conf.get("listeners", "")
        protos = _parse_listeners(listeners)
        all_protocols.update(protos)
        if "PLAINTEXT" in protos or "SASL_PLAINTEXT" in protos:
            plaintext_hosts.append((bid, listeners))

    has_tls_listener = any(p in ("SSL", "SASL_SSL") for p in all_protocols)
    if has_tls_listener and not plaintext_hosts:
        out.append(CheckResult("1.1", "Authentication/Encryption", "SASL/mTLS aktif untuk client-broker",
                                Status.PASS, f"[sumber: dashboard API] Listener terdeteksi: {sorted(all_protocols)}"))
        out.append(CheckResult("2.1", "Authentication/Encryption", "TLS aktif di listener",
                                Status.PASS, f"[sumber: dashboard API] Listener TLS ditemukan: {sorted(all_protocols)}"))
    elif has_tls_listener and plaintext_hosts:
        out.append(CheckResult("1.1", "Authentication/Encryption", "SASL/mTLS aktif untuk client-broker",
                                Status.WARN,
                                f"[sumber: dashboard API] Ada listener TLS DAN listener PLAINTEXT/SASL_PLAINTEXT sekaligus: {plaintext_hosts}",
                                "Pastikan listener non-TLS itu memang sengaja untuk internal-only, bukan exposed publik."))
        out.append(CheckResult("2.1", "Authentication/Encryption", "TLS aktif di listener",
                                Status.WARN, f"[sumber: dashboard API] Campuran TLS & non-TLS: {sorted(all_protocols)}"))
    else:
        out.append(CheckResult("1.1", "Authentication/Encryption", "SASL/mTLS aktif untuk client-broker",
                                Status.FAIL, f"[sumber: dashboard API] Tidak ada listener TLS terdeteksi: {sorted(all_protocols)}",
                                "Tambahkan listener SASL_SSL/SSL."))
        out.append(CheckResult("2.1", "Authentication/Encryption", "TLS aktif di listener",
                                Status.FAIL, f"[sumber: dashboard API] {sorted(all_protocols)}"))

    if plaintext_hosts:
        out.append(CheckResult("1.5", "Authentication/Encryption", "Mekanisme PLAIN tidak dipakai tanpa TLS",
                                Status.WARN,
                                f"[sumber: dashboard API] Listener SASL_PLAINTEXT/PLAINTEXT ditemukan di broker: {[b for b, _ in plaintext_hosts]}",
                                "Cek apakah listener ini reachable dari luar - kalau ya, ini risiko nyata."))
    else:
        out.append(CheckResult("1.5", "Authentication/Encryption", "Mekanisme PLAIN tidak dipakai tanpa TLS",
                                Status.PASS, "[sumber: dashboard API] Tidak ada listener PLAINTEXT/SASL_PLAINTEXT."))

    # 2.4 - versi TLS minimum: TIDAK bisa dicek dari config broker biasa (butuh raw socket ke broker asli)
    out.append(CheckResult("2.4", "Authentication/Encryption", "Minimal TLS 1.2, TLS 1.0/1.1 ditolak",
                            Status.SKIP, "Tidak bisa diverifikasi lewat dashboard API - butuh koneksi TLS langsung ke broker (lihat tool utama)."))
    out.append(CheckResult("2.2", "Authentication/Encryption", "Sertifikat dari CA terpercaya",
                            Status.SKIP, "Tidak bisa diverifikasi lewat dashboard API - butuh koneksi TLS langsung ke broker (lihat tool utama)."))

    # 1.2 - inter-broker protocol
    inter_results = []
    for bid, conf in valid.items():
        proto = _resolve_inter_broker_protocol(conf)
        inter_results.append((bid, proto))

    unresolved = [b for b, p in inter_results if not p]
    plaintext_inter = [b for b, p in inter_results if p and p.upper() == "PLAINTEXT"]
    if plaintext_inter:
        out.append(CheckResult("1.2", "Authentication/Encryption", "Autentikasi antar-broker bukan PLAINTEXT",
                                Status.FAIL, f"[sumber: dashboard API] Broker dengan inter-broker PLAINTEXT: {plaintext_inter}",
                                "Set security.inter.broker.protocol atau inter.broker.listener.name ke listener TLS."))
    elif unresolved and len(unresolved) == len(inter_results):
        out.append(CheckResult("1.2", "Authentication/Encryption", "Autentikasi antar-broker bukan PLAINTEXT",
                                Status.MANUAL, "[sumber: dashboard API] Tidak bisa resolve protokol inter-broker dari config yang tersedia."))
    else:
        out.append(CheckResult("1.2", "Authentication/Encryption", "Autentikasi antar-broker bukan PLAINTEXT",
                                Status.PASS, f"[sumber: dashboard API] {inter_results}"))

    return out


def check_authorization(client, broker_configs: dict) -> list:
    out = []
    valid = {bid: c for bid, c in broker_configs.items() if "__error__" not in c}

    # 3.1 - authorizer.class.name dari broker config
    authorizer_values = [(bid, c.get("authorizer.class.name")) for bid, c in valid.items()]
    no_authorizer = [b for b, v in authorizer_values if not v]

    acls, acl_err = client.get_acls()

    if no_authorizer and len(no_authorizer) == len(authorizer_values) and authorizer_values:
        out.append(CheckResult("3.1", "Authorization", "ACL authorizer aktif", Status.FAIL,
                                "[sumber: dashboard API] authorizer.class.name kosong di semua broker.",
                                "Aktifkan AclAuthorizer/StandardAuthorizer."))
    elif authorizer_values:
        out.append(CheckResult("3.1", "Authorization", "ACL authorizer aktif", Status.PASS,
                                f"[sumber: dashboard API] {authorizer_values}"))
    elif acl_err:
        # Tidak ada data broker config sama sekali, tapi endpoint ACL error - jadikan sinyal tidak langsung
        out.append(CheckResult("3.1", "Authorization", "ACL authorizer aktif", Status.WARN,
                                f"[sumber: dashboard API] Tidak bisa baca authorizer.class.name langsung, tapi endpoint /acls gagal: {acl_err}. "
                                "Ini KEMUNGKINAN (bukan pasti) menunjukkan authorizer tidak aktif - perlu konfirmasi manual.",
                                "Cross-check manual: coba describe ACL langsung ke broker, atau tanya tim infra."))
    else:
        out.append(CheckResult("3.1", "Authorization", "ACL authorizer aktif", Status.MANUAL,
                                "[sumber: dashboard API] Tidak ada data untuk disimpulkan."))

    # 3.2 - least privilege, hanya jika endpoint ACL sukses
    if acl_err:
        out.append(CheckResult("3.2", "Authorization", "ACL mengikuti least privilege", Status.ERROR,
                                f"[sumber: dashboard API] Endpoint /acls gagal: {acl_err}"))
    else:
        risky = [a for a in acls if a.get("resourceName") == "*" and a.get("permission") == "ALLOW"]
        if risky:
            out.append(CheckResult("3.2", "Authorization", "ACL mengikuti least privilege", Status.WARN,
                                    f"[sumber: dashboard API] {len(risky)} ACL wildcard ALLOW ditemukan, contoh: {risky[:3]}",
                                    "Tinjau ACL dengan resourceName='*' dan permission=ALLOW."))
        else:
            out.append(CheckResult("3.2", "Authorization", "ACL mengikuti least privilege", Status.PASS,
                                    f"[sumber: dashboard API] Total ACL: {len(acls)}, tidak ada wildcard ALLOW yang jelas."))

    # 3.3 - allow.everyone.if.no.acl.found
    allow_everyone = [(bid, c.get("allow.everyone.if.no.acl.found")) for bid, c in valid.items()
                       if c.get("allow.everyone.if.no.acl.found") is not None]
    if allow_everyone:
        bad = [b for b, v in allow_everyone if str(v).lower() == "true"]
        out.append(CheckResult("3.3", "Authorization", "Deny by default", Status.FAIL if bad else Status.PASS,
                                f"[sumber: dashboard API] {allow_everyone}"))
    else:
        out.append(CheckResult("3.3", "Authorization", "Deny by default", Status.MANUAL,
                                "[sumber: dashboard API] allow.everyone.if.no.acl.found tidak diset eksplisit."))

    return out


def check_broker_hardening(broker_configs: dict) -> list:
    out = []
    valid = {bid: c for bid, c in broker_configs.items() if "__error__" not in c}

    def get_all(key):
        return [(bid, c.get(key)) for bid, c in valid.items() if c.get(key) is not None]

    mapping = [
        ("6.1", "auto.create.topics.enable", "false", "auto.create.topics.enable dinonaktifkan"),
        ("6.3", "unclean.leader.election.enable", "false", "unclean.leader.election.enable dinonaktifkan"),
    ]
    for cid, key, expected, title in mapping:
        vals = get_all(key)
        if not vals:
            out.append(CheckResult(cid, "Broker Hardening", title, Status.MANUAL,
                                    f"[sumber: dashboard API] Config '{key}' tidak ditemukan eksplisit."))
            continue
        bad = [b for b, v in vals if str(v).lower() != expected]
        out.append(CheckResult(cid, "Broker Hardening", title,
                                Status.FAIL if bad else Status.PASS,
                                f"[sumber: dashboard API] {vals}"))

    vals = get_all("delete.topic.enable")
    if vals:
        risky = any(str(v).lower() == "true" for _, v in vals)
        out.append(CheckResult("6.2", "Broker Hardening", "delete.topic.enable dikombinasikan dgn ACL ketat",
                                Status.WARN if risky else Status.PASS, f"[sumber: dashboard API] {vals}"))
    else:
        out.append(CheckResult("6.2", "Broker Hardening", "delete.topic.enable dikombinasikan dgn ACL ketat",
                                Status.MANUAL, "[sumber: dashboard API] Config tidak ditemukan eksplisit."))

    for cid, title in [("6.4", "Broker dijalankan dengan user non-root"),
                        ("6.6", "JMX remote tanpa autentikasi dinonaktifkan")]:
        out.append(CheckResult(cid, "Broker Hardening", title, Status.SKIP,
                                "Tidak bisa diverifikasi lewat dashboard API - butuh akses OS-level (lihat tool utama, modul SSH)."))

    return out


def check_kraft_or_zk(broker_configs: dict) -> list:
    out = []
    valid = {bid: c for bid, c in broker_configs.items() if "__error__" not in c}
    has_process_roles = any(c.get("process.roles") for c in valid.values())
    if has_process_roles:
        out.append(CheckResult("5.2", "ZooKeeper/KRaft", "Mode cluster (KRaft vs ZooKeeper)", Status.PASS,
                                "[sumber: dashboard API] 'process.roles' ditemukan -> KRaft mode."))
    else:
        out.append(CheckResult("5.2", "ZooKeeper/KRaft", "Mode cluster (KRaft vs ZooKeeper)", Status.MANUAL,
                                "[sumber: dashboard API] 'process.roles' tidak ditemukan -> kemungkinan masih ZooKeeper, "
                                "tapi tidak 100% pasti hanya dari config ini."))
    return out


def check_dashboard_access_model(client) -> list:
    """Bukan item checklist bernomor - ini temuan kontekstual soal model akses dashboard itu sendiri."""
    out = []
    info, err = client.get_authorization_info()
    if err:
        out.append(CheckResult("DASH.1", "Dashboard Access Model", "Model kontrol akses dashboard",
                                Status.ERROR, f"[sumber: dashboard API] Gagal ambil /api/authorization: {err}"))
        return out

    rbac_enabled = info.get("rbacEnabled")
    username = (info.get("userInfo") or {}).get("username")
    if rbac_enabled is False:
        out.append(CheckResult("DASH.1", "Dashboard Access Model",
                                "Dashboard punya kontrol akses granular (bukan shared account)",
                                Status.WARN,
                                "[sumber: dashboard API] rbacEnabled=false -> dashboard TIDAK menerapkan role-based access "
                                f"control granular. Sesi ini login sebagai '{username}'. "
                                "Ini mengonfirmasi temuan: akses dashboard bersifat shared/tidak individual.",
                                "Pertimbangkan mengaktifkan RBAC di kafka-ui (dukungan OAuth/LDAP per user) "
                                "agar audit trail bisa dikaitkan ke individu, bukan 1 akun bersama."))
    elif rbac_enabled is True:
        out.append(CheckResult("DASH.1", "Dashboard Access Model",
                                "Dashboard punya kontrol akses granular (bukan shared account)",
                                Status.PASS,
                                f"[sumber: dashboard API] rbacEnabled=true, login sebagai '{username}'."))
    else:
        out.append(CheckResult("DASH.1", "Dashboard Access Model",
                                "Dashboard punya kontrol akses granular (bukan shared account)",
                                Status.MANUAL, "[sumber: dashboard API] Field rbacEnabled tidak ditemukan di response."))
    return out


def run_all_checks(client) -> list:
    results = []
    results += check_patch_version(client)

    broker_configs, err = client.get_all_broker_configs_merged()
    if err:
        results.append(CheckResult("BROKER.0", "Connection", "Berhasil ambil config broker lewat dashboard",
                                    Status.ERROR, f"[sumber: dashboard API] {err}"))
    results += check_authentication_and_encryption(broker_configs)
    results += check_authorization(client, broker_configs)
    results += check_broker_hardening(broker_configs)
    results += check_kraft_or_zk(broker_configs)
    results += check_dashboard_access_model(client)
    return results
