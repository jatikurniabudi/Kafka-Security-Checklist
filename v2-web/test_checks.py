"""
Test logic checks.py memakai mock ApiClient (tidak connect ke dashboard asli).
Jalankan: python -m pytest test_checks.py -v   atau   python test_checks.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kafka_ui_audit.checks import run_all_checks, check_authentication_and_encryption, check_broker_hardening
from kafka_ui_audit.models import Status


class MockApiClient:
    """Meniru ApiClient tapi mengembalikan data statis, tidak melakukan HTTP request."""

    def __init__(self, cluster_name="test-kafka", scenario="good"):
        self.cluster_name = cluster_name
        self.scenario = scenario

    def get_clusters(self):
        return [{"name": self.cluster_name, "version": "3.6.1", "features": ["KAFKA_ACL_VIEW"]}], None

    def get_cluster_stats(self):
        return {"version": "3.6.1", "activeControllers": 1}, None

    def get_brokers(self):
        return [{"id": 1}, {"id": 2}], None

    def get_broker_configs(self, broker_id):
        if self.scenario == "good":
            return [
                {"name": "listeners", "value": "SASL_SSL://0.0.0.0:9093"},
                {"name": "security.inter.broker.protocol", "value": "SASL_SSL"},
                {"name": "authorizer.class.name", "value": "kafka.security.authorizer.AclAuthorizer"},
                {"name": "allow.everyone.if.no.acl.found", "value": "false"},
                {"name": "auto.create.topics.enable", "value": "false"},
                {"name": "unclean.leader.election.enable", "value": "false"},
                {"name": "delete.topic.enable", "value": "false"},
            ], None
        elif self.scenario == "bad":
            return [
                {"name": "listeners", "value": "PLAINTEXT://0.0.0.0:9092"},
                {"name": "security.inter.broker.protocol", "value": "PLAINTEXT"},
                {"name": "authorizer.class.name", "value": ""},
                {"name": "allow.everyone.if.no.acl.found", "value": "true"},
                {"name": "auto.create.topics.enable", "value": "true"},
                {"name": "unclean.leader.election.enable", "value": "true"},
                {"name": "delete.topic.enable", "value": "true"},
            ], None
        elif self.scenario == "error":
            return None, "HTTP 403: Forbidden"

    def get_acls(self):
        if self.scenario == "good":
            return [{"resourceType": "TOPIC", "resourceName": "orders", "principal": "User:app1",
                      "operation": "READ", "permission": "ALLOW"}], None
        elif self.scenario == "bad":
            return None, "HTTP 500: SecurityDisabledException: No Authorizer is configured"
        return [], None

    def get_authorization_info(self):
        return {"rbacEnabled": False, "userInfo": {"username": "shared-account"}}, None

    def get_application_info(self):
        return {"build": {"version": "0.7.2"}}, None

    def get_all_broker_configs_merged(self):
        result = {}
        for b in [1, 2]:
            configs, err = self.get_broker_configs(b)
            if err:
                result[b] = {"__error__": err}
            else:
                result[b] = {c["name"]: c["value"] for c in configs}
        return result, None


def test_good_scenario():
    client = MockApiClient(scenario="good")
    results = run_all_checks(client)
    by_id = {r.id: r for r in results}

    assert by_id["1.1"].status == Status.PASS, by_id["1.1"].detail
    assert by_id["1.2"].status == Status.PASS, by_id["1.2"].detail
    assert by_id["3.1"].status == Status.PASS, by_id["3.1"].detail
    assert by_id["3.3"].status == Status.PASS, by_id["3.3"].detail
    assert by_id["6.1"].status == Status.PASS, by_id["6.1"].detail
    assert by_id["6.3"].status == Status.PASS, by_id["6.3"].detail
    assert by_id["DASH.1"].status == Status.WARN, "rbacEnabled=false harus WARN walau scenario 'good'"
    print("test_good_scenario: OK")


def test_bad_scenario():
    client = MockApiClient(scenario="bad")
    results = run_all_checks(client)
    by_id = {r.id: r for r in results}

    assert by_id["1.1"].status == Status.FAIL, by_id["1.1"].detail
    assert by_id["1.2"].status == Status.FAIL, by_id["1.2"].detail
    assert by_id["3.1"].status == Status.FAIL, by_id["3.1"].detail
    assert by_id["3.3"].status == Status.FAIL, by_id["3.3"].detail
    assert by_id["6.1"].status == Status.FAIL, by_id["6.1"].detail
    assert by_id["6.3"].status == Status.FAIL, by_id["6.3"].detail
    assert by_id["3.2"].status == Status.ERROR, "ACL endpoint gagal harus jadi ERROR bukan FAIL diam-diam"
    print("test_bad_scenario: OK")


def test_error_scenario():
    client = MockApiClient(scenario="error")
    results = run_all_checks(client)
    by_id = {r.id: r for r in results}
    # Semua config broker gagal -> harus ERROR, bukan exception yang crash
    assert by_id["1.1"].status == Status.ERROR, by_id["1.1"].detail
    print("test_error_scenario: OK (tidak crash saat semua config gagal diambil)")


if __name__ == "__main__":
    test_good_scenario()
    test_bad_scenario()
    test_error_scenario()
    print("\nSemua test lulus.")
