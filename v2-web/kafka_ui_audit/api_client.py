"""
Wrapper tipis di atas endpoint kafka-ui yang relevan untuk audit keamanan.
Path dikonfirmasi dari OpenAPI spec resmi:
https://github.com/provectus/kafka-ui/blob/master/kafka-ui-contract/src/main/resources/swagger/kafka-ui-api.yaml

Setiap fungsi mengembalikan tuple (data, error) - error berisi pesan string
kalau request gagal/status bukan 200, supaya caller bisa memutuskan status
CheckResult (ERROR vs informasi tambahan) tanpa exception menghentikan proses.
"""

import requests


class ApiClient:
    def __init__(self, session: requests.Session, base_url: str, cluster_name: str, timeout: int = 15):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.cluster_name = cluster_name
        self.timeout = timeout

    def _get(self, path: str, params=None):
        url = self.base_url + path
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            return None, f"Request gagal: {e}"

        if resp.status_code == 200:
            try:
                return resp.json(), None
            except ValueError:
                return None, f"Response bukan JSON valid (status 200): {resp.text[:200]}"
        else:
            body_snippet = resp.text[:300].replace("\n", " ")
            return None, f"HTTP {resp.status_code}: {body_snippet}"

    # ---- Endpoint-endpoint yang dipakai ----

    def get_clusters(self):
        """GET /api/clusters -> list of Cluster (name, version, features, dll)."""
        return self._get("/api/clusters")

    def get_cluster_stats(self):
        """GET /api/clusters/{clusterName}/stats -> ClusterStats (version, activeControllers, dll)."""
        return self._get(f"/api/clusters/{self.cluster_name}/stats")

    def get_brokers(self):
        """GET /api/clusters/{clusterName}/brokers -> list of Broker (id, host, port)."""
        return self._get(f"/api/clusters/{self.cluster_name}/brokers")

    def get_broker_configs(self, broker_id):
        """GET /api/clusters/{clusterName}/brokers/{id}/configs -> list of BrokerConfig."""
        return self._get(f"/api/clusters/{self.cluster_name}/brokers/{broker_id}/configs")

    def get_acls(self):
        """GET /api/clusters/{clusterName}/acls -> list of KafkaAcl.
        Bisa gagal (mis. 500) kalau broker tidak punya authorizer aktif - itu sendiri sinyal."""
        return self._get(f"/api/clusters/{self.cluster_name}/acls")

    def get_authorization_info(self):
        """GET /api/authorization -> AuthenticationInfo (rbacEnabled, userInfo.permissions)."""
        return self._get("/api/authorization")

    def get_application_info(self):
        """GET /api/info -> ApplicationInfo (versi kafka-ui itu sendiri, bukan versi Kafka)."""
        return self._get("/api/info")

    def get_all_broker_configs_merged(self):
        """Helper: ambil config semua broker, kembalikan dict broker_id -> {name: value}."""
        brokers, err = self.get_brokers()
        if err:
            return {}, err
        result = {}
        for b in brokers:
            bid = b.get("id")
            configs, cerr = self.get_broker_configs(bid)
            if cerr:
                result[bid] = {"__error__": cerr}
                continue
            result[bid] = {c["name"]: c.get("value") for c in configs}
        return result, None
