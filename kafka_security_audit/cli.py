import argparse
import sys

from .config import load_config
from .admin_checks import run_all_admin_checks
from .tls_checks import check_tls
from .zk_checks import check_zookeeper
from .ecosystem_checks import check_ecosystem
from .ssh_checks import run_all_ssh_checks
from .report import print_console_report, export_json, export_html


def main():
    parser = argparse.ArgumentParser(description="Kafka Security Audit Tool")
    parser.add_argument("-c", "--config", default="config.yaml", help="Path ke file config.yaml")
    parser.add_argument("--json", help="Export hasil ke file JSON")
    parser.add_argument("--html", help="Export hasil ke file HTML")
    parser.add_argument("--skip-ssh", action="store_true", help="Lewati semua pengecekan via SSH")
    parser.add_argument("--skip-zk", action="store_true", help="Lewati pengecekan ZooKeeper")
    parser.add_argument("--skip-ecosystem", action="store_true", help="Lewati pengecekan Connect/Schema Registry")
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        print(f"Config tidak ditemukan: {args.config}")
        print("Copy config.example.yaml ke config.yaml lalu sesuaikan.")
        sys.exit(1)

    all_results = []

    print("-> Menjalankan pengecekan via Kafka Admin API ...")
    all_results += run_all_admin_checks(cfg)

    print("-> Menjalankan pengecekan TLS langsung ke broker ...")
    all_results += check_tls(cfg)

    if not args.skip_zk:
        print("-> Menjalankan pengecekan ZooKeeper (jika dikonfigurasi) ...")
        all_results += check_zookeeper(cfg)

    if not args.skip_ecosystem:
        print("-> Menjalankan pengecekan Kafka Connect/Schema Registry (jika dikonfigurasi) ...")
        all_results += check_ecosystem(cfg)

    if not args.skip_ssh:
        print("-> Menjalankan pengecekan OS-level via SSH (jika dikonfigurasi) ...")
        all_results += run_all_ssh_checks(cfg)

    print_console_report(all_results)

    if args.json:
        export_json(all_results, args.json)
        print(f"Laporan JSON disimpan ke: {args.json}")
    if args.html:
        export_html(all_results, args.html)
        print(f"Laporan HTML disimpan ke: {args.html}")


if __name__ == "__main__":
    main()
