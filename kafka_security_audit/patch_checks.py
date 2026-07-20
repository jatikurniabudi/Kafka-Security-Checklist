"""
Cek versi Kafka broker dan bandingkan dengan daftar versi yang diketahui
punya CVE signifikan. Daftar ini TIDAK lengkap/live - selalu silangkan
dengan NVD (https://nvd.nist.gov) atau mailing list security Kafka
sebelum mengambil keputusan compliance.
"""

from .models import CheckResult, Status

# Daftar contoh, bukan daftar lengkap/terkini. Isi/timpa lewat config known_cve_versions.
DEFAULT_KNOWN_VULNERABLE = {
    # versi : catatan singkat
    "0.10": "Versi sangat lama, banyak CVE terakumulasi, sudah EOL lama.",
    "1.": "Seri 1.x sudah EOL, tidak menerima patch keamanan.",
    "2.0": "CVE-2019-12399 (JAAS config injection) - upgrade ke >=2.1.1/2.2.1/2.3.0.",
    "2.1": "CVE-2019-12399 - upgrade ke >=2.1.1.",
    "2.8.0": "Rentan terhadap sejumlah isu log4j 1.x tergantung dependency yang dibundel.",
}


def check_kafka_version(cfg, admin) -> list:
    out = []
    version = None
    try:
        # kafka-python menyimpan versi broker hasil ApiVersionsRequest di client internal
        version_tuple = admin._client.check_version()
        if version_tuple:
            version = ".".join(str(x) for x in version_tuple)
    except Exception as e:
        out.append(CheckResult("10.1", "Patch Management", "Kafka berjalan di versi yang masih didukung/patched",
                                Status.ERROR, f"Gagal mendeteksi versi broker: {e}",
                                "Cek manual lewat `kafka-broker-api-versions.sh` atau log startup broker."))
        return out

    known_bad = {**DEFAULT_KNOWN_VULNERABLE, **(cfg.known_cve_versions or {})}
    hit = None
    if version:
        for prefix, note in known_bad.items():
            if version.startswith(prefix):
                hit = note
                break

    if version is None:
        out.append(CheckResult("10.1", "Patch Management", "Kafka berjalan di versi yang masih didukung/patched",
                                Status.MANUAL, "Tidak bisa mendeteksi versi broker secara otomatis.",
                                "Cek manual versi broker dan bandingkan dengan advisory keamanan terbaru."))
    elif hit:
        out.append(CheckResult("10.1", "Patch Management", "Kafka berjalan di versi yang masih didukung/patched",
                                Status.FAIL, f"Terdeteksi versi {version}. {hit}",
                                "Upgrade ke versi Kafka stabil terbaru."))
    else:
        out.append(CheckResult("10.1", "Patch Management", "Kafka berjalan di versi yang masih didukung/patched",
                                Status.PASS, f"Terdeteksi versi {version}, tidak cocok dengan daftar versi bermasalah yang diketahui tool ini.",
                                "Tetap cross-check manual ke NVD/mailing list Kafka security untuk CVE terbaru."))

    out.append(CheckResult("10.2", "Patch Management", "Dependency (log4j, dll) sudah di-scan",
                            Status.MANUAL, "Perlu vulnerability scan terpisah (mis. Trivy/Grype) terhadap jar dependency broker.",
                            "Jalankan software composition analysis terhadap folder libs/ broker."))
    out.append(CheckResult("10.3", "Patch Management", "Sesuai standar compliance (CIS Benchmark, ISO 27001, dll)",
                            Status.MANUAL, "Perlu mapping manual ke kontrol compliance yang relevan bagi organisasi."))

    return out
