"""Load konfigurasi koneksi dari file YAML."""

import yaml
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class SSHTarget:
    host: str
    port: int = 22
    username: str = ""
    key_filename: Optional[str] = None
    password: Optional[str] = None
    role: str = "broker"  # broker | zookeeper


@dataclass
class EcosystemTarget:
    name: str
    url: str  # contoh: https://connect.internal:8083


@dataclass
class AuditConfig:
    bootstrap_servers: str
    security_protocol: str = "PLAINTEXT"  # PLAINTEXT | SSL | SASL_PLAINTEXT | SASL_SSL
    sasl_mechanism: Optional[str] = None
    sasl_username: Optional[str] = None
    sasl_password: Optional[str] = None
    ssl_cafile: Optional[str] = None
    ssl_certfile: Optional[str] = None
    ssl_keyfile: Optional[str] = None
    ssl_check_hostname: bool = True

    zookeeper_hosts: List[str] = field(default_factory=list)  # "host:port", kosong jika KRaft-only

    ssh_targets: List[SSHTarget] = field(default_factory=list)  # kosong = lewati semua cek SSH
    ecosystem_targets: List[EcosystemTarget] = field(default_factory=list)  # Kafka Connect / Schema Registry

    known_cve_versions: dict = field(default_factory=dict)  # override daftar versi rentan


def load_config(path: str) -> AuditConfig:
    with open(path, "r") as f:
        raw = yaml.safe_load(f) or {}

    ssh_targets = [SSHTarget(**t) for t in raw.get("ssh_targets", [])]
    ecosystem_targets = [EcosystemTarget(**t) for t in raw.get("ecosystem_targets", [])]

    kafka = raw.get("kafka", {})
    return AuditConfig(
        bootstrap_servers=kafka.get("bootstrap_servers", "localhost:9092"),
        security_protocol=kafka.get("security_protocol", "PLAINTEXT"),
        sasl_mechanism=kafka.get("sasl_mechanism"),
        sasl_username=kafka.get("sasl_username"),
        sasl_password=kafka.get("sasl_password"),
        ssl_cafile=kafka.get("ssl_cafile"),
        ssl_certfile=kafka.get("ssl_certfile"),
        ssl_keyfile=kafka.get("ssl_keyfile"),
        ssl_check_hostname=kafka.get("ssl_check_hostname", True),
        zookeeper_hosts=raw.get("zookeeper_hosts", []),
        ssh_targets=ssh_targets,
        ecosystem_targets=ecosystem_targets,
        known_cve_versions=raw.get("known_cve_versions", {}),
    )
