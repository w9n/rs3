#!/usr/bin/env python3
"""Semantic regression checks for the chart's fail-closed NetworkPolicy."""

from __future__ import annotations

import copy
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts" / "rs3-gateway"


def local_values() -> dict[str, object]:
    return {
        "admin": {
            "profile": "local",
            "createToken": True,
            "bearerToken": "fixture-admin-token-12345",
        },
        "credentials": {
            "create": True,
            "accessKeyId": "fixture-access-key",
            "secretAccessKey": "fixture-secret-key",
        },
        "repositoryKeys": {
            "create": True,
            "saltHex": "11" * 32,
            "wrappingKeyHex": "22" * 32,
        },
        "networkPolicy": {"enabled": True},
    }


def production_values() -> dict[str, object]:
    return {
        "admin": {
            "profile": "production",
            "existingTokenSecret": "fixture-admin-token",
        },
        "image": {"digest": f"sha256:{'0' * 64}"},
        "backend": {"endpoint": "https://s3.example.invalid"},
        "credentials": {"existingSecret": "fixture-client-credentials"},
        "repositoryKeys": {"existingSecret": "fixture-repository-keys"},
        "repository": {"retention": {"mode": "governance", "days": 30}},
        "providerConformance": {
            "existingConfigMap": "fixture-provider-conformance"
        },
        "recovery": {"publicKey": f"ed25519:{'0' * 64}"},
        "metrics": {"enabled": True},
        "networkPolicy": {
            "enabled": True,
            "ingress": {
                "namespaceSelector": {
                    "matchLabels": {"kubernetes.io/metadata.name": "backup-clients"}
                },
                "metrics": {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "monitoring"}
                    },
                    "podSelector": {"matchLabels": {"app": "prometheus"}},
                },
            },
            "egress": {
                "backend": {"to": [{"ipBlock": {"cidr": "10.20.0.0/16"}}]},
                "kubeApi": {"to": [{"ipBlock": {"cidr": "10.96.0.1/32"}}]},
                "dns": {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {
                                    "kubernetes.io/metadata.name": "kube-system"
                                }
                            },
                            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                        }
                    ]
                },
            },
        },
    }


def render(values: dict[str, object], *, succeeds: bool = True) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as values_file:
        yaml.safe_dump(values, values_file)
        values_file.flush()
        result = subprocess.run(
            ["helm", "template", "rs3", str(CHART), "-f", values_file.name],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    if succeeds and result.returncode != 0:
        raise AssertionError(result.stderr)
    if not succeeds and result.returncode == 0:
        raise AssertionError("Helm unexpectedly accepted unsafe NetworkPolicy values")
    return result.stdout


def documents(output: str) -> Iterator[dict[str, object]]:
    for document in yaml.safe_load_all(output):
        if isinstance(document, dict):
            yield document


def network_policy(output: str) -> dict[str, object]:
    policies = [doc for doc in documents(output) if doc.get("kind") == "NetworkPolicy"]
    if len(policies) != 1:
        raise AssertionError(f"expected one NetworkPolicy, got {len(policies)}")
    return policies[0]


def port_set(rule: dict[str, object]) -> frozenset[tuple[str, int]]:
    ports = rule.get("ports")
    if not isinstance(ports, list):
        raise AssertionError("NetworkPolicy rule has no ports")
    return frozenset((port["protocol"], port["port"]) for port in ports)


def rules_for_ports(
    rules: list[dict[str, object]], expected: frozenset[tuple[str, int]]
) -> list[dict[str, object]]:
    return [rule for rule in rules if port_set(rule) == expected]


def main() -> None:
    local = network_policy(render(local_values()))
    local_spec = local["spec"]
    assert local_spec["ingress"] == []
    assert local_spec["egress"] == []

    values = production_values()
    production = network_policy(render(values))
    spec = production["spec"]
    ingress = spec["ingress"]
    egress = spec["egress"]
    assert len(ingress) == 2
    assert len(egress) == 3
    assert all(rule.get("from") for rule in ingress)
    assert all(rule.get("to") for rule in egress)
    assert {port_set(rule) for rule in ingress} == {
        frozenset({("TCP", 9080)}),
        frozenset({("TCP", 9082)}),
    }
    assert [port_set(rule) for rule in egress].count(frozenset({("TCP", 443)})) == 2
    assert frozenset({("UDP", 53), ("TCP", 53)}) in {
        port_set(rule) for rule in egress
    }

    network_values = values["networkPolicy"]
    ingress_values = network_values["ingress"]
    s3_rule = rules_for_ports(ingress, frozenset({("TCP", 9080)}))
    metrics_rule = rules_for_ports(ingress, frozenset({("TCP", 9082)}))
    assert [rule["from"] for rule in s3_rule] == [
        [{"namespaceSelector": ingress_values["namespaceSelector"]}]
    ]
    assert [rule["from"] for rule in metrics_rule] == [
        [ingress_values["metrics"]]
    ]

    egress_values = network_values["egress"]
    https_peers = [
        rule["to"] for rule in rules_for_ports(egress, frozenset({("TCP", 443)}))
    ]
    assert https_peers == [
        egress_values["backend"]["to"],
        egress_values["kubeApi"]["to"],
    ]
    dns_rule = rules_for_ports(egress, frozenset({("UDP", 53), ("TCP", 53)}))
    assert [rule["to"] for rule in dns_rule] == [egress_values["dns"]["to"]]

    unsafe_defaults = production_values()
    unsafe_defaults["networkPolicy"] = {"enabled": True}
    render(unsafe_defaults, succeeds=False)

    mixed_peer = copy.deepcopy(production_values())
    backend = mixed_peer["networkPolicy"]["egress"]["backend"]
    backend["to"][0]["namespaceSelector"] = {"matchLabels": {"tenant": "backup"}}
    render(mixed_peer, succeeds=False)

    missing_provider_evidence = copy.deepcopy(production_values())
    missing_provider_evidence["providerConformance"]["existingConfigMap"] = ""
    render(missing_provider_evidence, succeeds=False)

    unsafe_retention_window = copy.deepcopy(production_values())
    unsafe_retention_window["repository"]["retention"]["days"] = 14
    render(unsafe_retention_window, succeeds=False)


if __name__ == "__main__":
    main()
