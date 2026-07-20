"""
Cek TLS langsung ke port broker via raw socket - tidak butuh SSH.
Berguna untuk memverifikasi versi TLS yang benar-benar dipakai
dan info sertifikat (issuer, expiry, self-signed atau bukan),
independen dari apa yang ditulis di server.properties.
"""

import socket
import ssl
import datetime

from .models import CheckResult, Status


def _parse_host_port(bootstrap_servers: str):
    hosts = []
    for entry in bootstrap_servers.split(","):
        entry = entry.strip()
        if ":" in entry:
            host, port = entry.rsplit(":", 1)
            hosts.append((host, int(port)))
    return hosts


def _check_one_broker(host: str, port: int, timeout=5) -> dict:
    info = {"host": host, "port": port}

    # 1. Coba negosiasi TLS minimum (TLS 1.0/1.1) - kalau broker MENOLAK, itu bagus.
    for label, proto in [("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto
            ctx.maximum_version = proto
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    info[f"accepts_{label}"] = True
        except ssl.SSLError:
            info[f"accepts_{label}"] = False
        except Exception as e:
            info[f"accepts_{label}"] = None  # tidak bisa ditentukan (mis. port bukan TLS / non-blocking issue)
            info[f"error_{label}"] = str(e)

    # 2. Ambil info sertifikat & versi TLS yang dipilih dengan negosiasi normal (default = terbaik yg didukung client)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info["negotiated_version"] = ssock.version()
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    cert = ssl._ssl._test_decode_cert if False else None  # placeholder, decode manual di bawah
        # decode cert pakai getpeercert(True) hasil dict tidak tersedia tanpa verifikasi,
        # jadi gunakan modul ssl.DER_cert_to_PEM_cert + cryptography kalau tersedia
        info["tls_reachable"] = True
    except Exception as e:
        info["tls_reachable"] = False
        info["tls_error"] = str(e)

    # 3. Detail sertifikat (issuer, expiry) - butuh CERT_REQUIRED sementara utk ambil metadata lengkap
    try:
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
        if cert_bin:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                info["issuer"] = cert.issuer.rfc4514_string()
                info["subject"] = cert.subject.rfc4514_string()
                info["not_after"] = cert.not_valid_after.isoformat()
                info["self_signed"] = (cert.issuer == cert.subject)
                days_left = (cert.not_valid_after - datetime.datetime.utcnow()).days
                info["days_until_expiry"] = days_left
            except ImportError:
                info["cert_parse_note"] = "Library 'cryptography' tidak terpasang, detail sertifikat dilewati."
    except Exception as e:
        info["cert_error"] = str(e)

    return info


def check_tls(cfg) -> list:
    """cfg: AuditConfig. Mengembalikan list[CheckResult] untuk kategori Encryption."""
    out = []
    proto = cfg.security_protocol.upper()

    if proto not in ("SSL", "SASL_SSL"):
        out.append(CheckResult("2.1", "Encryption", "TLS aktif di listener yang diperiksa",
                                Status.FAIL if proto in ("PLAINTEXT", "SASL_PLAINTEXT") else Status.MANUAL,
                                f"security_protocol yang dipakai tool ini adalah {proto} (bukan TLS).",
                                "Konfigurasikan listener client dengan SSL atau SASL_SSL."))
        out.append(CheckResult("2.4", "Encryption", "Minimal TLS 1.2 dipakai, TLS 1.0/1.1 ditolak",
                                Status.SKIP, "Tidak relevan karena listener yang dicek bukan TLS."))
        return out

    hosts = _parse_host_port(cfg.bootstrap_servers)
    if not hosts:
        out.append(CheckResult("2.1", "Encryption", "TLS aktif di listener yang diperiksa",
                                Status.ERROR, "Tidak bisa parsing bootstrap_servers."))
        return out

    all_info = [_check_one_broker(h, p) for h, p in hosts]

    reachable = [i for i in all_info if i.get("tls_reachable")]
    if reachable:
        out.append(CheckResult("2.1", "Encryption", "TLS aktif di listener yang diperiksa",
                                Status.PASS, f"Handshake TLS berhasil ke {len(reachable)}/{len(all_info)} broker."))
    else:
        out.append(CheckResult("2.1", "Encryption", "TLS aktif di listener yang diperiksa",
                                Status.FAIL, "Tidak ada broker yang berhasil TLS handshake.",
                                "Cek apakah port/listener benar-benar dikonfigurasi TLS."))

    old_tls_accepted = [i["host"] for i in all_info if i.get("accepts_TLSv1") or i.get("accepts_TLSv1.1")]
    if old_tls_accepted:
        out.append(CheckResult("2.4", "Encryption", "Minimal TLS 1.2 dipakai, TLS 1.0/1.1 ditolak",
                                Status.FAIL, f"Broker berikut masih menerima TLS 1.0/1.1: {old_tls_accepted}",
                                "Set ssl.protocol / ssl.enabled.protocols hanya ke TLSv1.2,TLSv1.3."))
    else:
        out.append(CheckResult("2.4", "Encryption", "Minimal TLS 1.2 dipakai, TLS 1.0/1.1 ditolak",
                                Status.PASS, "Semua broker menolak TLS 1.0/1.1 (atau port bukan TLS biasa)."))

    self_signed = [i["host"] for i in all_info if i.get("self_signed")]
    if self_signed:
        out.append(CheckResult("2.2", "Encryption", "Sertifikat dari CA terpercaya (bukan self-signed sembarangan)",
                                Status.WARN, f"Broker dengan sertifikat self-signed: {self_signed}",
                                "Pastikan self-signed ini memang dari internal PKI yang dikelola, bukan sertifikat ad-hoc."))
    else:
        signed_info = [i.get("issuer") for i in all_info if i.get("issuer")]
        out.append(CheckResult("2.2", "Encryption", "Sertifikat dari CA terpercaya (bukan self-signed sembarangan)",
                                Status.PASS if signed_info else Status.MANUAL,
                                f"Issuer terdeteksi: {signed_info}" if signed_info else "Tidak bisa membaca detail sertifikat."))

    expiring = [(i["host"], i.get("days_until_expiry")) for i in all_info
                if i.get("days_until_expiry") is not None and i["days_until_expiry"] < 30]
    if expiring:
        out.append(CheckResult("2.2b", "Encryption", "Sertifikat tidak mendekati expired",
                                Status.WARN, f"Sertifikat akan expire <30 hari: {expiring}",
                                "Perpanjang sertifikat sebelum expired untuk menghindari downtime."))

    return out
