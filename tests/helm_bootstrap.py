#!/usr/bin/env python3
"""Bootstrap resources, evidence ownership, credentials and startup ordering."""
import copy

from helm_runtime_limits import documents, local_values, render


def values():
    result = local_values()
    result.update({
        "bootstrap": {"enabled": True},
        "backend": {"endpoint": "http://fixture:9000", "prefix": "repository"},
        "repository": {"retention": {"mode": "compliance", "days": 30}},
    })
    return result


def one(docs, kind):
    found = [doc for doc in docs if doc["kind"] == kind]
    assert len(found) == 1, (kind, len(found))
    return found[0]


def env(container):
    items = container["env"]
    result = {item["name"]: item for item in items}
    assert len(items) == len(result), "duplicate environment variables"
    return result


def historical_reader_preserves_bindings(production):
    original = list(documents(render(production)))
    writer = one(original, "Deployment")["spec"]["template"]["spec"]
    writer_env = env(writer["containers"][0])
    writer_lease_rules = [rule for rule in one(original, "Role")["rules"] if "leases" in rule["resources"]]
    assert writer_lease_rules == [
        {"apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["create"]},
        {"apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "resourceNames": [writer_env["RS3_ANCHOR_NAME"]["value"]], "verbs": ["get", "update"]},
    ]
    journal = env(one(original, "Job")["spec"]["template"]["spec"]["containers"][0])["RS3_INIT_JOURNAL_SECRET"]["value"]
    reader = copy.deepcopy(production)
    reader["bootstrap"] = {"enabled": False, "existingJournalSecret": journal}
    reader["gateway"] = {"mode": "restore-readonly"}
    reader["recovery"] = {"point": "18446744073709551615"}
    docs = list(documents(render(reader)))
    pod = one(docs, "Deployment")["spec"]["template"]["spec"]
    gateway = pod["containers"][0]
    assert gateway["args"] == ["serve", "--recovery-point", "18446744073709551615"]
    assert "initContainers" not in pod
    assert not any(doc["kind"] in {"Job", "Secret"} for doc in docs)
    reader_env = env(gateway)
    for name in (
        "RS3_REPOSITORY_ID", "RS3_REPOSITORY_SALT_HEX", "RS3_KEYRING_WRAPPING_KEY_HEX",
        "RS3_KEYRING_ENVELOPE_OBJECT_ID", "RS3_STATIC_ACCESS_KEY_ID",
        "RS3_STATIC_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "RS3_ADMIN_BEARER_TOKEN", "RS3_ANCHOR_NAME", "RS3_ANCHOR_NAMESPACE",
        "RS3_PROVIDER_CONFORMANCE_REPORT_FILE", "RS3_BACKEND_PREFIX",
    ):
        assert reader_env[name] == writer_env[name], name
    assert reader_env["RS3_ALLOW_REPOSITORY_INIT"]["value"] == "false"
    assert reader_env["RS3_RECLAMATION_ENABLED"]["value"] == "false"
    assert "RS3_MAINTENANCE_MODE" not in reader_env
    evidence = next(volume for volume in pod["volumes"] if volume["name"] == "provider-conformance")
    assert evidence["secret"]["secretName"] == journal
    assert evidence["secret"]["items"] == [{"key": "provider-conformance.json", "path": "report.json"}]
    assert not any("secrets" in rule["resources"] for rule in one(docs, "Role")["rules"])
    assert one(docs, "Role")["rules"] == [{
        "apiGroups": ["coordination.k8s.io"], "resources": ["leases"],
        "resourceNames": [writer_env["RS3_ANCHOR_NAME"]["value"]], "verbs": ["get"],
    }]
    for point in ("0", "42", "9007199254740993"):
        reader["recovery"]["point"] = point
        assert one(list(documents(render(reader))), "Deployment")["spec"]["template"]["spec"]["containers"][0]["args"][-1] == point
    for point in (42, -1, "-1", "01", "1.5", "18446744073709551616", "1e3"):
        reader["recovery"]["point"] = point
        render(reader, succeeds=False)
    reader["recovery"]["point"] = "42"
    for section, field, value in (
        ("gateway", "mode", "read-write"), ("bootstrap", "enabled", True),
        ("repository", "allowInit", True), ("maintenance", "mode", "auto"),
    ):
        invalid = copy.deepcopy(reader)
        invalid.setdefault(section, {})[field] = value
        render(invalid, succeeds=False)
    reader["providerConformance"] = {"existingConfigMap": "external-evidence"}
    pod = one(list(documents(render(reader))), "Deployment")["spec"]["template"]["spec"]
    evidence = next(volume for volume in pod["volumes"] if volume["name"] == "provider-conformance")
    assert evidence["configMap"]["name"] == "external-evidence" and "secret" not in evidence


def main():
    ordinary = list(documents(render(local_values())))
    ordinary_rules = one(ordinary, "Role")["rules"]
    assert ordinary_rules[0]["verbs"] == ["create"]
    assert ordinary_rules[1]["verbs"] == ["get", "update"]
    assert all("secrets" not in rule["resources"] for rule in ordinary_rules)
    config = values()
    docs = list(documents(render(config)))
    job = one(docs, "Job")
    deployment = one(docs, "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    job_pod = job["spec"]["template"]["spec"]
    gateway = pod["containers"][0]
    wait = pod["initContainers"][0]
    init = job_pod["containers"][0]
    assert wait["args"][0] == "wait-for-init" and init["args"][0] == "init"
    assert "helm.sh/hook" not in job["metadata"].get("annotations", {})
    assert job_pod["serviceAccountName"] == pod["serviceAccountName"]
    assert init["image"] == wait["image"] == gateway["image"]
    assert env(wait) == env(gateway)
    init_env = env(init)
    serve_env = env(gateway)
    assert init_env["RS3_ALLOW_REPOSITORY_INIT"]["value"] == "true"
    assert serve_env["RS3_ALLOW_REPOSITORY_INIT"]["value"] == "false"
    assert "RS3_PROVIDER_CONFORMANCE_REPORT_FILE" not in init_env
    assert "RS3_PROVIDER_CONFORMANCE_REPORT_FILE" in serve_env
    for name in set(init_env) & set(serve_env) - {"RS3_ALLOW_REPOSITORY_INIT"}:
        assert init_env[name] == serve_env[name], name
    journal_name = init_env["RS3_INIT_JOURNAL_SECRET"]["value"]
    journal = next(doc for doc in docs if doc["kind"] == "Secret" and doc["metadata"]["name"] == journal_name)
    assert "data" not in journal and "stringData" not in journal
    assert journal["metadata"]["annotations"]["rs3.rs/bootstrap-journal"] == "v1"
    secret_rules = [rule for rule in one(docs, "Role")["rules"] if "secrets" in rule["resources"]]
    assert secret_rules == [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": [journal_name], "verbs": ["get", "update"]}]
    service_selector = one(docs, "Service")["spec"]["selector"]
    assert service_selector["app.kubernetes.io/component"] == "gateway"
    assert job["spec"]["template"]["metadata"]["labels"]["app.kubernetes.io/component"] != "gateway"
    assert one(list(documents(render(config))), "Job")["metadata"]["name"] == job["metadata"]["name"]
    # helm template renders revision 1; live upgrades change the revision so a
    # repeated command after a failed Job creates a new Job.
    assert "-init-r1-" in job["metadata"]["name"] and len(job["metadata"]["name"]) <= 63
    assert job["spec"]["backoffLimit"] == 3
    changed = copy.deepcopy(config)
    changed["image"] = {"tag": "next-build"}
    assert one(list(documents(render(changed))), "Job")["metadata"]["name"] != job["metadata"]["name"]
    external = copy.deepcopy(config)
    external["bootstrap"]["existingJournalSecret"] = "owned-journal"
    external["providerConformance"] = {"existingConfigMap": "owned-evidence"}
    external_docs = list(documents(render(external)))
    assert not any(doc["kind"] == "Secret" and doc["metadata"]["name"] == "owned-journal" for doc in external_docs)
    assert not any(doc["kind"] == "ConfigMap" for doc in external_docs)
    external_job = one(external_docs, "Job")["spec"]["template"]["spec"]
    assert "RS3_PROVIDER_CONFORMANCE_REPORT_FILE" in env(external_job["containers"][0])
    assert external_job["volumes"][1]["configMap"]["name"] == "owned-evidence"
    for section, field, value in [
        ("anchor", "mode", "memory"), ("anchor", "namespace", "other"),
        ("gateway", "mode", "restore-readonly"), ("gateway", "writerGuard", "off"),
        ("backend", "endpoint", "file:///data"), ("backend", "prefix", ""),
        ("repository", "allowInit", True), ("bootstrap", "timeoutSeconds", 0),
    ]:
        invalid = copy.deepcopy(config)
        invalid.setdefault(section, {})[field] = value
        render(invalid, succeeds=False)
    production = {
        "bootstrap": {"enabled": True},
        "image": {"digest": "sha256:" + "a" * 64},
        "backend": {"endpoint": "https://fixture.invalid"},
        "credentials": {"existingSecret": "fixture-client"},
        "backendCredentials": {"existingSecret": "fixture-backend"},
        "repositoryKeys": {"existingSecret": "fixture-keys"},
        "admin": {"existingTokenSecret": "fixture-admin"},
        "repository": {"retention": {"mode": "compliance", "days": 30}},
    }
    invalid_local = local_values()
    invalid_local["recovery"] = {"point": "42"}
    render(invalid_local, succeeds=False)
    production_docs = list(documents(render(production)))
    assert "RS3_RECOVERY_PUBLIC_KEY" not in env(one(production_docs, "Job")["spec"]["template"]["spec"]["containers"][0])
    historical_reader_preserves_bindings(production)
    production["recovery"] = {"publicKey": "invalid"}
    render(production, succeeds=False)
    production["recovery"]["publicKey"] = "ed25519:" + "a" * 64
    render(production)


if __name__ == "__main__":
    main()
