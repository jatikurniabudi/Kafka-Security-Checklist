"""Model hasil pengecekan. Sengaja diduplikasi dari tool pertama (bukan di-import)
supaya kedua tool ini benar-benar independen - sesuai permintaan untuk pembanding."""

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    MANUAL = "MANUAL"
    SKIP = "SKIP"
    ERROR = "ERROR"
    INFO = "INFO"   # temuan kontekstual, bukan pass/fail checklist langsung


@dataclass
class CheckResult:
    id: str
    category: str
    title: str
    status: Status
    detail: str = ""
    recommendation: str = ""
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
