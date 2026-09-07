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


def main():
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
        "repositoryKeys": {"existingSecret": "fixture-keys"},
        "admin": {"existingTokenSecret": "fixture-admin"},
        "repository": {"retention": {"mode": "compliance", "days": 30}},
    }
    production_docs = list(documents(render(production)))
    assert "RS3_RECOVERY_PUBLIC_KEY" not in env(one(production_docs, "Job")["spec"]["template"]["spec"]["containers"][0])
    production["recovery"] = {"publicKey": "invalid"}
    render(production, succeeds=False)
    production["recovery"]["publicKey"] = "ed25519:" + "a" * 64
    render(production)


if __name__ == "__main__":
    main()
