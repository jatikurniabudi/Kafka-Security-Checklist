# Kafka UI Dashboard Security Audit (Tool Sementara/Pembanding)

Tool ini **terpisah total** dari tool audit utama (`kafka-security-audit`). Dibuat
karena akses ke cluster Kafka `xxx-kafka` di environment ini **hanya tersedia lewat
dashboard kafka-ui**, tanpa jalur native Kafka protocol (AdminClient) maupun VPN ke
jaringan broker.

## Cara kerja

1. Login otomatis ke dashboard (form login) memakai username/password dari `.env`.
2. Setelah dapat session cookie, tool memanggil endpoint REST kafka-ui yang relevan
   (dikonfirmasi dari [OpenAPI spec resmi provectus/kafka-ui](https://github.com/provectus/kafka-ui/blob/master/kafka-ui-contract/src/main/resources/swagger/kafka-ui-api.yaml)).
3. Data dipetakan ke item checklist yang sama dengan tool utama - **tapi hanya untuk
   item yang memang bisa dijawab dari data yang diekspos dashboard.**

## Instalasi & Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# edit .env: isi KAFKA_UI_BASE_URL, KAFKA_UI_CLUSTER_NAME, KAFKA_UI_USERNAME, KAFKA_UI_PASSWORD
```

**Kalau login otomatis gagal** (`LOGIN GAGAL: ...` di output), kemungkinan besar path
endpoint atau nama field form login dashboard kamu berbeda dari default. Buka Network
tab browser saat login manual, cari request `POST` yang mengirim username/password,
lalu sesuaikan `KAFKA_UI_LOGIN_SUBMIT_PATH`, `KAFKA_UI_USERNAME_FIELD`,
`KAFKA_UI_PASSWORD_FIELD` di `.env`.

## Menjalankan

```bash
python -m kafka_ui_audit.cli -e .env --json report.json --html report.html
```

## Test tanpa koneksi asli

Logic pengecekan sudah divalidasi dengan mock data (skenario baik/buruk/error) tanpa
perlu koneksi ke dashboard:

```bash
python test_checks.py
```

---

## Perbandingan dengan Tool Utama (`kafka-security-audit`)

| Aspek | Tool Utama (AdminClient) | Tool Ini (Dashboard API) |
|---|---|---|
| Cara akses | Native Kafka protocol (TCP langsung ke broker) | REST API dashboard kafka-ui (HTTP + session login) |
| Prasyarat | Bootstrap server reachable, kredensial SASL cluster | URL dashboard reachable, kredensial login dashboard |
| Ketergantungan | `kafka-python` | `requests` + form login (rapuh terhadap perubahan endpoint login) |
| Kedalaman data broker | Semua config via `DescribeConfigs` | Sama persis (`/brokers/{id}/configs` expose config yang sama) untuk broker yang ditampilkan dashboard |
| ACL | `DescribeAcls` langsung ke broker | `/acls` endpoint - **tergantung endpoint ini berfungsi**; kalau error 500 justru jadi sinyal tidak langsung |
| TLS versi & sertifikat | Cek langsung via raw socket ke broker | **Tidak bisa** - dashboard tidak expose ini |
| Network/VPC/firewall | Manual (di luar cakupan keduanya) | Manual (di luar cakupan keduanya) |
| OS-level (non-root, JMX, file permission) | Modul SSH opsional | **Tidak bisa** - tidak ada SSH lewat dashboard |
| Isu tambahan yang justru ditemukan | - | `rbacEnabled=false` mengonfirmasi shared-account, tidak ada audit trail individual |

### Item checklist per kategori

| # | Item | Tool Utama | Tool Ini |
|---|---|---|---|
| 1.1 | SASL/mTLS client-broker | Ya (dari koneksi aktual) | Ya (dari string `listeners` config) |
| 1.2 | Inter-broker bukan PLAINTEXT | Ya | Ya |
| 1.5 | PLAIN tanpa TLS | Ya | Ya (parsial, dari listener string) |
| 2.1 | TLS aktif | Ya (raw socket) | Ya (dari config, tidak diverifikasi langsung) |
| 2.2 | Sertifikat CA terpercaya | Ya | **Tidak** |
| 2.4 | TLS versi minimum | Ya | **Tidak** |
| 3.1 | ACL authorizer aktif | Ya | Ya (langsung dari config, atau sinyal tidak langsung dari error `/acls`) |
| 3.2 | ACL least privilege | Ya | Ya (kalau endpoint `/acls` berhasil) |
| 3.3 | Deny by default | Ya | Ya |
| 4.x | Network/VPC/firewall | Manual | Manual |
| 5.2 | KRaft vs ZooKeeper | Ya | Ya (dari `process.roles`) |
| 6.1 | `auto.create.topics.enable` | Ya | Ya |
| 6.2 | `delete.topic.enable` + ACL | Ya | Ya |
| 6.3 | `unclean.leader.election.enable` | Ya | Ya |
| 6.4 | Non-root user | SSH opsional | **Tidak** |
| 6.6 | JMX remote auth | SSH opsional (parsial) | **Tidak** |
| 10.1 | Versi Kafka vs CVE | Ya | Ya |
| - | Model akses dashboard (shared account) | - | **Ya (temuan tambahan, `DASH.1`)** |

## Batasan penting untuk disampaikan ke management

1. **Ini bukan pengganti audit native.** Data broker config yang diekspos dashboard
   memang cocok dengan hasil `DescribeConfigs`, tapi kebenarannya bergantung pada
   apakah kafka-ui sendiri tidak memodifikasi/nge-cache data itu, dan bergantung pada
   izin akun dashboard yang dipakai (kalau akun read-only terbatas, sebagian endpoint
   bisa gagal dengan 403).
2. **Endpoint `/acls` yang error bisa punya lebih dari satu penyebab** - bisa karena
   authorizer memang tidak aktif (temuan security), atau karena akun dashboard tidak
   punya izin untuk melihat ACL (masalah permission tool, bukan broker). Perlu
   dikonfirmasi manual sebelum disimpulkan sebagai kegagalan konfigurasi.
3. **Login form otomatis rapuh** - kalau dashboard update dan mengubah flow login
   (misalnya tambah CAPTCHA, ganti ke OAuth), tool ini akan berhenti berfungsi dan
   perlu disesuaikan lagi.
4. Temuan `DASH.1` (shared account, tidak ada RBAC) **sebaiknya jadi rekomendasi
   utama** ke management terlepas dari hasil checklist lainnya - ini mempengaruhi
   kualitas audit trail untuk semua aktivitas di cluster ini.
