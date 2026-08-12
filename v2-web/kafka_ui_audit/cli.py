import argparse
import sys

from .config import load_config
from .auth import login, LoginError
from .api_client import ApiClient
from .checks import run_all_checks
from .report import print_console_report, export_json, export_html


def main():
    parser = argparse.ArgumentParser(description="Kafka UI Dashboard Security Audit (tool sementara/pembanding)")
    parser.add_argument("-e", "--env", default=".env", help="Path ke file .env")
    parser.add_argument("--json", help="Export hasil ke file JSON")
    parser.add_argument("--html", help="Export hasil ke file HTML")
    args = parser.parse_args()

    try:
        cfg = load_config(args.env)
    except (FileNotFoundError, ValueError) as e:
        print(f"Config error: {e}")
        sys.exit(1)

    print(f"-> Login ke {cfg.base_url} sebagai '{cfg.username}' ...")
    try:
        session = login(cfg)
    except LoginError as e:
        print(f"LOGIN GAGAL: {e}")
        sys.exit(1)
    print("-> Login berhasil.")

    client = ApiClient(session, cfg.base_url, cfg.cluster_name, cfg.request_timeout)

    print("-> Menjalankan pengecekan lewat dashboard API ...")
    results = run_all_checks(client)

    source_note = f"{cfg.base_url} (cluster: {cfg.cluster_name}) via kafka-ui REST API"
    print_console_report(results, source_note)

    if args.json:
        export_json(results, args.json, source_note)
        print(f"Laporan JSON disimpan ke: {args.json}")
    if args.html:
        export_html(results, args.html, source_note)
        print(f"Laporan HTML disimpan ke: {args.html}")


if __name__ == "__main__":
    main()
