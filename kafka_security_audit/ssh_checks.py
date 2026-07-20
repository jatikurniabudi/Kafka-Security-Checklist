"""
Pengecekan OS-level via SSH - OPSIONAL.
Hanya jalan jika user mengisi `ssh_targets` di config.yaml.
Butuh library 'paramiko'.

Item yang dicek di sini adalah yang TIDAK BISA diverifikasi lewat
Kafka Admin API: user proses, permission file config, isi server.properties
mentah, JMX flags di startup script.
"""

from .models import CheckResult, Status


def _run(ssh, cmd, timeout=10):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    return out, err


def check_ssh_target(target) -> list:
    out = []
    try:
        import paramiko
    except ImportError:
        out.append(CheckResult("SSH.0", "SSH Checks", f"Koneksi SSH ke {target.host}",
                                Status.ERROR, "Library 'paramiko' tidak terpasang.",
                                "pip install paramiko"))
        return out

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=target.host,
            port=target.port,
            username=target.username,
            key_filename=target.key_filename,
            password=target.password,
            timeout=10,
        )
    except Exception as e:
        out.append(CheckResult("SSH.0", "SSH Checks", f"Koneksi SSH ke {target.host}",
                                Status.ERROR, f"Gagal konek: {e}"))
        return out

    try:
        if target.role == "broker":
            out += _check_broker_host(client, target.host)
        elif target.role == "zookeeper":
            out += _check_zk_host(client, target.host)
    finally:
        client.close()

    return out


def _check_broker_host(ssh, host) -> list:
    out = []

    # 6.4 - user non-root
    proc_out, _ = _run(ssh, "ps -eo user,cmd | grep -i kafka.Kafka | grep -v grep")
    if not proc_out:
        out.append(CheckResult("6.4", "Broker Hardening", f"[{host}] Broker dijalankan dengan user non-root",
                                Status.MANUAL, "Tidak menemukan proses Kafka lewat 'ps' - mungkin nama proses berbeda atau di container.",
                                "Cek manual proses Kafka berjalan sebagai user apa."))
    else:
        lines = proc_out.splitlines()
        root_procs = [l for l in lines if l.strip().startswith("root")]
        if root_procs:
            out.append(CheckResult("6.4", "Broker Hardening", f"[{host}] Broker dijalankan dengan user non-root",
                                    Status.FAIL, f"Proses berjalan sebagai root: {root_procs}",
                                    "Jalankan broker dengan dedicated user (mis. 'kafka'), bukan root."))
        else:
            out.append(CheckResult("6.4", "Broker Hardening", f"[{host}] Broker dijalankan dengan user non-root",
                                    Status.PASS, f"{lines}"))

    # 8.3 - permission file config
    perm_out, _ = _run(ssh, "find /etc/kafka /opt/kafka* -maxdepth 2 -iname 'server.properties' -exec ls -l {} \\; 2>/dev/null")
    if perm_out:
        out.append(CheckResult("8.3", "Secrets Management", f"[{host}] Permission file config broker dibatasi",
                                Status.MANUAL, f"Ditemukan: {perm_out}. Periksa apakah permission <= 640.",
                                "chmod 640 server.properties, chown ke user service Kafka."))
    else:
        out.append(CheckResult("8.3", "Secrets Management", f"[{host}] Permission file config broker dibatasi",
                                Status.MANUAL, "Tidak menemukan file server.properties di path standar - sesuaikan path pencarian.",
                                "Sesuaikan lokasi file di ssh_checks.py bila instalasi custom."))

    # 6.6 - JMX remote flags
    jmx_out, _ = _run(ssh, "ps -eo cmd | grep -i kafka.Kafka | grep -i jmxremote | grep -v grep")
    if jmx_out:
        if "jmxremote.authenticate=true" in jmx_out:
            out.append(CheckResult("6.6", "Broker Hardening", f"[{host}] JMX remote memakai autentikasi",
                                    Status.PASS, "Ditemukan jmxremote.authenticate=true di command line."))
        else:
            out.append(CheckResult("6.6", "Broker Hardening", f"[{host}] JMX remote memakai autentikasi",
                                    Status.FAIL, "JMX remote aktif tapi authenticate tidak diset true.",
                                    "Set -Dcom.sun.management.jmxremote.authenticate=true dan ssl=true."))
    else:
        out.append(CheckResult("6.6", "Broker Hardening", f"[{host}] JMX remote memakai autentikasi",
                                Status.PASS, "Tidak terdeteksi flag JMX remote di command line proses (JMX remote kemungkinan tidak diaktifkan)."))

    return out


def _check_zk_host(ssh, host) -> list:
    out = []
    conf_out, _ = _run(ssh, "cat /etc/zookeeper/conf/zoo.cfg /opt/zookeeper*/conf/zoo.cfg 2>/dev/null")
    if not conf_out:
        out.append(CheckResult("5.1c", "ZooKeeper/KRaft", f"[{host}] Konfigurasi ZooKeeper ditemukan",
                                Status.MANUAL, "zoo.cfg tidak ditemukan di path standar.",
                                "Sesuaikan path pencarian di ssh_checks.py."))
        return out

    has_auth = "authProvider" in conf_out or "quorum.auth.enableSasl=true" in conf_out
    out.append(CheckResult("5.1c", "ZooKeeper/KRaft", f"[{host}] ZooKeeper SASL auth provider dikonfigurasi",
                            Status.PASS if has_auth else Status.FAIL,
                            "authProvider/quorum SASL ditemukan." if has_auth else "Tidak ditemukan konfigurasi SASL di zoo.cfg.",
                            "" if has_auth else "Tambahkan authProvider.1=org.apache.zookeeper.server.auth.SASLAuthenticationProvider dan aktifkan quorum SASL."))
    return out


def run_all_ssh_checks(cfg) -> list:
    out = []
    if not cfg.ssh_targets:
        out.append(CheckResult("SSH.SKIP", "SSH Checks", "Pengecekan OS-level (non-root, file permission, JMX)",
                                Status.SKIP, "Tidak ada ssh_targets di config - semua item OS-level jadi MANUAL di kategori lain."))
        return out
    for target in cfg.ssh_targets:
        out += check_ssh_target(target)
    return out
