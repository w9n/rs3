#!/usr/bin/env python3
"""Semantic checks for Helm hardening limits and backend timeouts."""

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
        raise AssertionError("Helm unexpectedly accepted incoherent runtime limits")
    return result.stdout


def documents(output: str) -> Iterator[dict[str, object]]:
    for document in yaml.safe_load_all(output):
        if isinstance(document, dict):
            yield document


def deployment_env(output: str) -> dict[str, str]:
    deployments = [doc for doc in documents(output) if doc.get("kind") == "Deployment"]
    if len(deployments) != 1:
        raise AssertionError(f"expected one Deployment, got {len(deployments)}")
    containers = deployments[0]["spec"]["template"]["spec"]["containers"]
    env = containers[0]["env"]
    return {entry["name"]: entry["value"] for entry in env if "value" in entry}


def main() -> None:
    defaults = deployment_env(render(local_values()))
    assert defaults["RS3_MAX_PUT_OBJECT_BYTES"] == "5368709120"
    assert defaults["RS3_BUFFERED_PUT_OBJECT_BYTES"] == "67108864"
    assert defaults["RS3_BACKEND_MULTIPART_PART_BYTES"] == "16777216"
    assert defaults["RS3_STREAM_READ_STALL_TIMEOUT_SECS"] == "30"
    assert defaults["RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES"] == "536870912"
    assert defaults["RS3_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES"] == "536870912"
    assert defaults["RS3_MAX_CONCURRENT_CONNECTIONS"] == "1024"
    assert defaults["RS3_MAX_CONCURRENT_REQUESTS"] == "256"
    assert defaults["RS3_REQUEST_RATE_LIMIT_PER_SECOND"] == "1024"
    assert defaults["RS3_BACKEND_CONNECT_TIMEOUT_SECS"] == "5"
    assert defaults["RS3_BACKEND_READ_TIMEOUT_SECS"] == "30"
    assert defaults["RS3_BACKEND_OPERATION_ATTEMPT_TIMEOUT_SECS"] == "120"
    assert defaults["RS3_BACKEND_OPERATION_TIMEOUT_SECS"] == "300"
    assert defaults["RS3_BACKEND_STALLED_STREAM_GRACE_SECS"] == "30"

    custom = local_values()
    custom["hardening"] = {
        "maxPutObjectBytes": 104_857_600,
        "bufferedPutObjectBytes": 10_485_760,
        "backendMultipartPartBytes": 5_242_880,
        "streamReadStallTimeoutSeconds": 7,
        "maxInFlightUploadBodyBytes": 31_457_280,
        "maxInFlightDownloadBodyBytes": 31_457_280,
        "maxConcurrentConnections": 64,
        "maxConcurrentRequests": 32,
        "requestRateLimitPerSecond": 128,
    }
    custom["backend"] = {
        "endpoint": "file:///data",
        "bucket": "backend",
        "prefix": "repository",
        "region": "us-east-1",
        "timeouts": {
            "connectSeconds": 3,
            "readSeconds": 4,
            "operationAttemptSeconds": 20,
            "operationSeconds": 40,
            "stalledStreamGraceSeconds": 6,
        },
    }
    configured = deployment_env(render(custom))
    assert configured["RS3_BUFFERED_PUT_OBJECT_BYTES"] == "10485760"
    assert configured["RS3_MAX_IN_FLIGHT_UPLOAD_BODY_BYTES"] == "31457280"
    assert configured["RS3_MAX_IN_FLIGHT_DOWNLOAD_BODY_BYTES"] == "31457280"
    assert configured["RS3_MAX_CONCURRENT_CONNECTIONS"] == "64"
    assert configured["RS3_MAX_CONCURRENT_REQUESTS"] == "32"
    assert configured["RS3_BACKEND_CONNECT_TIMEOUT_SECS"] == "3"
    assert configured["RS3_BACKEND_OPERATION_TIMEOUT_SECS"] == "40"

    buffered_above_max = copy.deepcopy(custom)
    buffered_above_max["hardening"]["bufferedPutObjectBytes"] = 104_857_601
    render(buffered_above_max, succeeds=False)

    insufficient_upload_budget = copy.deepcopy(custom)
    insufficient_upload_budget["hardening"]["maxInFlightUploadBodyBytes"] = 1
    render(insufficient_upload_budget, succeeds=False)

    oversized_multipart_part = copy.deepcopy(custom)
    oversized_multipart_part["hardening"]["backendMultipartPartBytes"] = 5_368_709_121
    render(oversized_multipart_part, succeeds=False)

    overflowing_multipart_arithmetic = copy.deepcopy(custom)
    overflowing_multipart_arithmetic["hardening"] = {
        "maxPutObjectBytes": 5_368_709_120,
        "bufferedPutObjectBytes": 1,
        "backendMultipartPartBytes": 4_612_000_000_000_000_000,
        "streamReadStallTimeoutSeconds": 1,
        "maxInFlightUploadBodyBytes": 1,
        "maxInFlightDownloadBodyBytes": 1,
        "maxConcurrentConnections": 1,
        "maxConcurrentRequests": 1,
        "requestRateLimitPerSecond": 1,
    }
    render(overflowing_multipart_arithmetic, succeeds=False)

    large_payload_segments = copy.deepcopy(custom)
    large_payload_segments["repository"] = {"payloadSegmentSizeBytes": 67_108_864}
    render(large_payload_segments, succeeds=False)

    large_payload_segments["hardening"]["maxInFlightUploadBodyBytes"] = 222_310_400
    large_segment_env = deployment_env(render(large_payload_segments))
    assert large_segment_env["RS3_PAYLOAD_SEGMENT_SIZE_BYTES"] == "67108864"

    zero_payload_segment = copy.deepcopy(custom)
    zero_payload_segment["repository"] = {"payloadSegmentSizeBytes": 0}
    render(zero_payload_segment, succeeds=False)

    zero_connection_limit = copy.deepcopy(custom)
    zero_connection_limit["hardening"]["maxConcurrentConnections"] = 0
    render(zero_connection_limit, succeeds=False)

    excessive_request_limit = copy.deepcopy(custom)
    excessive_request_limit["hardening"]["maxConcurrentRequests"] = 2**61
    render(excessive_request_limit, succeeds=False)

    connect_above_attempt = copy.deepcopy(custom)
    connect_above_attempt["backend"]["timeouts"]["connectSeconds"] = 21
    render(connect_above_attempt, succeeds=False)

    attempt_above_operation = copy.deepcopy(custom)
    attempt_above_operation["backend"]["timeouts"]["operationAttemptSeconds"] = 41
    render(attempt_above_operation, succeeds=False)


if __name__ == "__main__":
    main()
