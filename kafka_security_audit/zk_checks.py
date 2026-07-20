"""
Pengecekan ZooKeeper opsional. Butuh library 'kazoo' dan daftar
zookeeper_hosts di config. Kalau tidak diisi, modul ini dilewati
sepenuhnya oleh runner utama.
"""

from .models import CheckResult, Status


def check_zookeeper(cfg) -> list:
    out = []
    if not cfg.zookeeper_hosts:
        return out  # sudah ditangani sebagai SKIP di admin_checks

    try:
        from kazoo.client import KazooClient
    except ImportError:
        out.append(CheckResult("5.1b", "ZooKeeper/KRaft", "Detail keamanan ZooKeeper",
                                Status.ERROR, "Library 'kazoo' tidak terpasang.",
                                "pip install kazoo, lalu jalankan ulang."))
        return out

    hosts = ",".join(cfg.zookeeper_hosts)
    try:
        zk = KazooClient(hosts=hosts, timeout=5)
        zk.start(timeout=5)
        try:
            # Cek ACL pada root znode /
            acls, stat = zk.get_acls("/")
            open_acl = any(a.perms == 31 and str(a.id) == "world:'anyone" for a in acls)  # 31 = ALL perms
            if open_acl or not acls:
                out.append(CheckResult("5.1b", "ZooKeeper/KRaft", "ACL root znode ZooKeeper tidak 'world:anyone'",
                                        Status.FAIL, f"ACL pada '/': {acls}",
                                        "Batasi ACL znode Kafka hanya untuk principal broker (SASL)."))
            else:
                out.append(CheckResult("5.1b", "ZooKeeper/KRaft", "ACL root znode ZooKeeper tidak 'world:anyone'",
                                        Status.PASS, f"ACL pada '/': {acls}"))
        finally:
            zk.stop()
            zk.close()
    except Exception as e:
        out.append(CheckResult("5.1b", "ZooKeeper/KRaft", "Detail keamanan ZooKeeper",
                                Status.ERROR, f"Gagal konek ke ZooKeeper: {e}",
                                "Pastikan zookeeper_hosts benar dan bisa diakses dari mesin tool ini."))
    return out
