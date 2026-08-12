"""
Load konfigurasi dari file .env (bukan config.yaml, sesuai preferensi:
kredensial dibaca dari file terpisah, bukan dihardcode/di-paste manual tiap run).
"""

import os
from dataclasses import dataclass
from dotenv import load_dotenv


@dataclass
class DashboardConfig:
    base_url: str
    cluster_name: str
    username: str
    password: str

    login_page_path: str      # halaman yang di-GET dulu untuk ambil CSRF token/cookie awal (jika ada)
    login_submit_path: str    # endpoint yang menerima POST username+password
    username_field: str
    password_field: str

    verify_tls: bool
    request_timeout: int


def load_config(env_path: str = ".env") -> DashboardConfig:
    if not os.path.exists(env_path):
        raise FileNotFoundError(
            f"File {env_path} tidak ditemukan. Copy dari .env.example lalu isi kredensial."
        )
    load_dotenv(env_path, override=True)

    def req(key):
        val = os.getenv(key)
        if not val:
            raise ValueError(f"Env var '{key}' wajib diisi di {env_path}")
        return val

    return DashboardConfig(
        base_url=req("KAFKA_UI_BASE_URL").rstrip("/"),
        cluster_name=req("KAFKA_UI_CLUSTER_NAME"),
        username=req("KAFKA_UI_USERNAME"),
        password=req("KAFKA_UI_PASSWORD"),
        login_page_path=os.getenv("KAFKA_UI_LOGIN_PAGE_PATH", "/auth"),
        login_submit_path=os.getenv("KAFKA_UI_LOGIN_SUBMIT_PATH", "/login"),
        username_field=os.getenv("KAFKA_UI_USERNAME_FIELD", "username"),
        password_field=os.getenv("KAFKA_UI_PASSWORD_FIELD", "password"),
        verify_tls=os.getenv("KAFKA_UI_VERIFY_TLS", "true").lower() != "false",
        request_timeout=int(os.getenv("KAFKA_UI_TIMEOUT", "15")),
    )
