"""
Login otomatis ke dashboard kafka-ui memakai username/password dari .env.

Alurnya (khas Spring Security form-login yang dipakai kafka-ui):
1. GET halaman login dulu - untuk dapat cookie sesi awal & (kalau ada) CSRF token
   yang tersembunyi di HTML atau di header response.
2. POST username+password (+ CSRF token kalau ditemukan) ke endpoint submit login.
3. Verifikasi login berhasil dengan memanggil endpoint yang butuh auth
   (/api/authorization) - kalau masih di-redirect ke halaman login, berarti gagal.

PENTING: path & nama field di sini adalah TEBAKAN TERBAIK berdasarkan konvensi
Spring Security default. Kalau login gagal, buka Network tab browser saat kamu
login manual, lihat request POST-nya (biasanya bernama mirip '/login' atau '/auth'),
lalu sesuaikan KAFKA_UI_LOGIN_SUBMIT_PATH, KAFKA_UI_USERNAME_FIELD,
KAFKA_UI_PASSWORD_FIELD di .env supaya cocok.
"""

import re
import requests

from .config import DashboardConfig


class LoginError(Exception):
    pass


def _extract_csrf_token(html: str):
    """Coba beberapa pola umum tempat CSRF token disisipkan di halaman login."""
    patterns = [
        r'name="_csrf"\s+value="([^"]+)"',
        r'name="csrf" content="([^"]+)"',
        r'<meta name="_csrf" content="([^"]+)"',
    ]
    for p in patterns:
        m = re.search(p, html)
        if m:
            return m.group(1)
    return None


def login(cfg: DashboardConfig) -> requests.Session:
    session = requests.Session()
    session.verify = cfg.verify_tls

    # Step 1: GET halaman login untuk ambil cookie awal + CSRF token (jika ada)
    login_page_url = cfg.base_url + cfg.login_page_path
    resp = session.get(login_page_url, timeout=cfg.request_timeout)
    csrf_token = _extract_csrf_token(resp.text)

    # Step 2: POST kredensial
    submit_url = cfg.base_url + cfg.login_submit_path
    payload = {
        cfg.username_field: cfg.username,
        cfg.password_field: cfg.password,
    }
    if csrf_token:
        payload["_csrf"] = csrf_token

    resp2 = session.post(
        submit_url,
        data=payload,
        timeout=cfg.request_timeout,
        allow_redirects=True,
        headers={"Referer": login_page_url},
    )

    # Step 3: Verifikasi - panggil endpoint yang butuh auth
    check_url = cfg.base_url + "/api/authorization"
    resp3 = session.get(check_url, timeout=cfg.request_timeout, allow_redirects=False)

    if resp3.status_code == 200:
        return session

    # Login gagal - kumpulkan info diagnostik supaya user bisa sesuaikan .env
    raise LoginError(
        "Login otomatis gagal. Status /api/authorization setelah login: "
        f"{resp3.status_code}. "
        f"Status POST login: {resp2.status_code} (redirect ke: {resp2.url}). "
        "Kemungkinan KAFKA_UI_LOGIN_SUBMIT_PATH / nama field username-password / "
        "kebutuhan CSRF token di .env belum sesuai dengan yang dipakai dashboard ini. "
        "Cek Network tab browser saat login manual untuk menyesuaikan."
    )
