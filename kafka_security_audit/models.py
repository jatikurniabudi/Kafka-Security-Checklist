"""Data model untuk hasil setiap pengecekan keamanan."""

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    MANUAL = "MANUAL"   # tidak bisa diverifikasi otomatis, perlu review manusia
    SKIP = "SKIP"        # tidak dicek karena prasyarat tidak terpenuhi (mis. tidak ada akses SSH)
    ERROR = "ERROR"      # pengecekan gagal dijalankan (exception, koneksi gagal, dll)


@dataclass
class CheckResult:
    id: str                 # contoh: "1.1"
    category: str           # contoh: "Authentication"
    title: str               # deskripsi singkat item checklist
    status: Status
    detail: str = ""         # apa yang ditemukan
    recommendation: str = ""  # apa yang harus dilakukan jika FAIL/WARN
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "status": self.status.value,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "extra": self.extra,
        }
