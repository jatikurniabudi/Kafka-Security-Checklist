"""
Cek keamanan dasar Kafka Connect REST API dan Schema Registry:
apakah endpoint bisa diakses tanpa kredensial sama sekali, dan apakah
jalan di atas HTTPS.
"""

import requests
from urllib.parse import urlparse

from .models import CheckResult, Status


def check_ecosystem(cfg) -> list:
    out = []
    if not cfg.ecosystem_targets:
        out.append(CheckResult("9.0", "Ecosystem", "Kafka Connect / Schema Registry diamankan",
                                Status.SKIP, "Tidak ada ecosystem_targets di config - lewati pengecekan ini."))
        return out

    for target in cfg.ecosystem_targets:
        parsed = urlparse(target.url)
        check_id_base = f"9.{target.name}"

        # HTTPS check
        if parsed.scheme != "https":
            out.append(CheckResult(f"{check_id_base}.1", "Ecosystem",
                                    f"{target.name}: endpoint menggunakan HTTPS",
                                    Status.FAIL, f"URL {target.url} tidak menggunakan HTTPS.",
                                    "Aktifkan TLS pada REST API Kafka Connect/Schema Registry."))
        else:
            out.append(CheckResult(f"{check_id_base}.1", "Ecosystem",
                                    f"{target.name}: endpoint menggunakan HTTPS",
                                    Status.PASS, f"URL {target.url} sudah HTTPS."))

        # Auth check - coba akses tanpa kredensial
        try:
            resp = requests.get(target.url, timeout=5, verify=False)
            if resp.status_code in (401, 403):
                out.append(CheckResult(f"{check_id_base}.2", "Ecosystem",
                                        f"{target.name}: REST API menolak akses tanpa kredensial",
                                        Status.PASS, f"Status code {resp.status_code} tanpa auth."))
            elif resp.status_code == 200:
                out.append(CheckResult(f"{check_id_base}.2", "Ecosystem",
                                        f"{target.name}: REST API menolak akses tanpa kredensial",
                                        Status.FAIL,
                                        f"Endpoint mengembalikan 200 OK TANPA kredensial apapun.",
                                        "Aktifkan autentikasi (Basic Auth/mTLS/OAuth) pada REST API ini."))
            else:
                out.append(CheckResult(f"{check_id_base}.2", "Ecosystem",
                                        f"{target.name}: REST API menolak akses tanpa kredensial",
                                        Status.MANUAL, f"Status code tidak biasa: {resp.status_code}, cek manual."))
        except requests.exceptions.RequestException as e:
            out.append(CheckResult(f"{check_id_base}.2", "Ecosystem",
                                    f"{target.name}: REST API menolak akses tanpa kredensial",
                                    Status.ERROR, f"Gagal mengakses endpoint: {e}"))

    out.append(CheckResult("9.3", "Ecosystem", "Custom connector plugin divalidasi/di-sandbox",
                            Status.MANUAL, "Perlu review proses approval jar connector pihak ketiga - tidak bisa dicek via REST.",
                            "Terapkan proses review/whitelist sebelum jar connector di-deploy ke plugin.path."))
    return out
