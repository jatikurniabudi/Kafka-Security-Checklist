# Kafka Security Audit Tool

Tool CLI Python untuk mengotomasi pengecekan checklist keamanan Apache Kafka.
Memetakan langsung ke checklist 10 kategori (Authentication, Encryption,
Authorization, Network, ZooKeeper/KRaft, Broker Hardening, Audit & Monitoring,
Secrets Management, Ecosystem, Patch Management).

## Prinsip desain

- **Default-nya remote-only**: cukup kredensial Kafka client (bootstrap servers +
  SASL/TLS) untuk sebagian besar cek. Tidak wajib akses SSH ke broker.
- **SSH opsional**: beberapa item (user non-root, permission file config, flag JMX)
  memang tidak bisa diverifikasi lewat Kafka API — kalau kamu isi `ssh_targets`
  di config, tool ini akan mengeceknya juga.
- **Jujur soal keterbatasan**: item yang memang tidak bisa diverifikasi otomatis
  (kebijakan rotasi kredensial, VPC/firewall, integrasi SIEM, dll) ditandai
  `MANUAL` di laporan — bukan di-skip diam-diam. Checklist aslinya tetap 100%
  tercermin di laporan, sisanya jadi pengingat untuk direview manual.

## Instalasi

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`paramiko` dan `kazoo` hanya dipakai kalau kamu mengisi `ssh_targets` /
`zookeeper_hosts`. Kalau tidak dipakai, boleh dihapus dari requirements.

## Setup

```bash
cp config.example.yaml config.yaml
# edit config.yaml: bootstrap_servers, security_protocol, credential, dst.
```

**Kredensial yang dipakai tool ini sebaiknya:**
- read-only sebisa mungkin (butuh izin `DESCRIBE_CONFIGS` di cluster dan
  `DESCRIBE` untuk cek ACL — bukan izin admin penuh)
- disimpan lewat environment variable / secret manager, bukan hardcoded di
  `config.yaml` yang di-commit ke git

## Menjalankan

```bash
python -m kafka_security_audit.cli -c config.yaml
```

Dengan export laporan:

```bash
python -m kafka_security_audit.cli -c config.yaml --json report.json --html report.html
```

Melewati modul tertentu:

```bash
python -m kafka_security_audit.cli -c config.yaml --skip-ssh --skip-zk --skip-ecosystem
```

## Arti status di laporan

| Status  | Arti |
|---------|------|
| PASS    | Item checklist terpenuhi |
| FAIL    | Item checklist tidak terpenuhi — ada rekomendasi perbaikan |
| WARN    | Terpenuhi sebagian / berpotensi risiko, perlu ditinjau |
| MANUAL  | Tidak bisa diverifikasi otomatis — perlu review manusia |
| SKIP    | Tidak relevan (mis. item ZooKeeper saat cluster KRaft) atau prasyarat config kosong |
| ERROR   | Pengecekan gagal dijalankan (koneksi gagal, permission kurang, dst) — bukan berarti FAIL |

## Struktur modul

```
kafka_security_audit/
  admin_checks.py     -> Authentication, Authorization, Broker Hardening, Network, ZK/KRaft mode, via Kafka AdminClient
  tls_checks.py        -> Encryption: cek TLS version & sertifikat langsung via socket
  zk_checks.py          -> Detail ACL ZooKeeper (opsional, butuh kazoo)
  ssh_checks.py          -> Item OS-level (non-root, file permission, JMX) - opsional, butuh paramiko
  ecosystem_checks.py    -> Kafka Connect / Schema Registry REST API
  patch_checks.py        -> Deteksi versi Kafka vs known CVE
  report.py               -> Output console + export JSON/HTML
  config.py                -> Loader config.yaml
  models.py                 -> Struktur data CheckResult
```

## Menambah pengecekan baru

Setiap pengecekan mengembalikan `CheckResult(id, category, title, status, detail, recommendation)`.
Tambahkan fungsi baru di modul yang relevan, lalu daftarkan di `cli.py` atau
di `run_all_admin_checks()` / `run_all_ssh_checks()`.

## Batasan yang perlu diketahui

- **Permission tool ini menentukan seberapa dalam cek bisa jalan.** Kalau
  credential yang dipakai tool ini tidak punya izin `DESCRIBE_CONFIGS`, banyak
  item akan `ERROR`, bukan `FAIL` — itu bukan berarti brokernya aman, cek
  permission credential-nya dulu.
- Daftar versi Kafka rentan di `patch_checks.py` **bukan daftar CVE live** —
  hanya contoh. Selalu silangkan dengan [NVD](https://nvd.nist.gov) atau
  mailing list keamanan Apache Kafka untuk keputusan compliance.
- Tool ini adalah alat bantu audit, bukan pengganti penetration test atau
  review keamanan menyeluruh oleh tim security.
