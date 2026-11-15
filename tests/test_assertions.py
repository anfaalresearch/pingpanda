"""Tests for HTTP health assertions, response-time SLA validation, and custom request headers."""

from __future__ import annotations

import csv
import json
import re
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from pingpanda.assertions import (
    AssertionConfig,
    evaluate_assertions,
    parse_expect_header_option,
    parse_header_option,
    parse_status_codes,
)
from pingpanda.checkpoint import load_checkpoint, save_checkpoint
from pingpanda.cli import build_assertion_config, parse_arguments
from pingpanda.models import UrlResult
from pingpanda.network import check_url_status
from pingpanda.report import (
    extract_scan_metrics,
    format_result_line,
    generate_csv_report,
    generate_json_report,
    generate_markdown_report,
    generate_text_report,
)


# ==============================================================================
# 1. Parsing Status Codes
# ==============================================================================

def test_parse_status_codes_single_code():
    assert parse_status_codes("200") == {200}
    assert parse_status_codes("404") == {404}


def test_parse_status_codes_comma_separated():
    assert parse_status_codes("200, 204, 301") == {200, 204, 301}


def test_parse_status_codes_range():
    assert parse_status_codes("200-204") == {200, 201, 202, 203, 204}


def test_parse_status_codes_mixed_ranges_and_singles():
    assert parse_status_codes("200-202, 204, 301-302") == {200, 201, 202, 204, 301, 302}


@pytest.mark.parametrize(
    "invalid_spec",
    [
        "",
        "   ",
        "abc",
        "200-abc",
        "300-200",  # inverted range
        "50-99",    # < 100
        "200-605",  # > 599
        "200-300-400",
        "99",
        "600",
    ],
)
def test_parse_status_codes_invalid_raises_value_error(invalid_spec):
    with pytest.raises(ValueError):
        parse_status_codes(invalid_spec)


# ==============================================================================
# 2. Parsing Headers
# ==============================================================================

def test_parse_header_option_valid():
    name, val = parse_header_option("Authorization: Bearer secret-token-123")
    assert name == "Authorization"
    assert val == "Bearer secret-token-123"

    name, val = parse_header_option("  X-Custom-Header :  value with spaces  ")
    assert name == "X-Custom-Header"
    assert val == "value with spaces"


@pytest.mark.parametrize(
    "invalid_header",
    [
        "",
        "NoColonHere",
        ": value_without_name",
        "   : value",
    ],
)
def test_parse_header_option_invalid(invalid_header):
    with pytest.raises(ValueError):
        parse_header_option(invalid_header)


def test_parse_expect_header_option():
    name, val = parse_expect_header_option("Content-Type: application/json")
    assert name == "Content-Type"
    assert val == "application/json"

    name, val = parse_expect_header_option("X-Request-Id")
    assert name == "X-Request-Id"
    assert val is None


@pytest.mark.parametrize(
    "invalid_expect_header",
    [
        "",
        "   ",
        ": value",
    ],
)
def test_parse_expect_header_option_invalid(invalid_expect_header):
    with pytest.raises(ValueError):
        parse_expect_header_option(invalid_expect_header)


# ==============================================================================
# 3. Assertion Evaluation Engine
# ==============================================================================

def test_evaluate_assertions_none_or_empty_config():
    passed, failures, sla_breached = evaluate_assertions(200, {}, "ok", 0.05, None)
    assert passed is None
    assert failures == []
    assert not sla_breached

    empty_config = AssertionConfig()
    passed, failures, sla_breached = evaluate_assertions(200, {}, "ok", 0.05, empty_config)
    assert passed is None
    assert failures == []
    assert not sla_breached


def test_evaluate_assertions_status_code():
    config = AssertionConfig(expect_status={200, 204})

    passed, failures, sla_breached = evaluate_assertions(200, {}, "", 0.05, config)
    assert passed is True
    assert failures == []

    passed, failures, sla_breached = evaluate_assertions(404, {}, "", 0.05, config)
    assert passed is False
    assert any("404 not in expected set" in f for f in failures)


def test_evaluate_assertions_body_substring():
    config = AssertionConfig(expect_body="system healthy")

    passed, failures, _ = evaluate_assertions(200, {}, '{"status": "system healthy"}', 0.05, config)
    assert passed is True

    passed, failures, _ = evaluate_assertions(200, {}, '{"status": "degraded"}', 0.05, config)
    assert passed is False
    assert any("missing expected text: 'system healthy'" in f for f in failures)


def test_evaluate_assertions_body_regex():
    config = AssertionConfig(expect_body_regex=re.compile(r'"uptime":\s*\d+'))

    passed, failures, _ = evaluate_assertions(200, {}, '{"uptime": 3600, "ok": true}', 0.05, config)
    assert passed is True

    passed, failures, _ = evaluate_assertions(200, {}, '{"error": "down"}', 0.05, config)
    assert passed is False
    assert any("does not match regex" in f for f in failures)


def test_evaluate_assertions_header_presence_and_value():
    config = AssertionConfig(
        expect_headers={
            "content-type": "application/json",
            "x-trace-id": None,  # presence check only
        }
    )

    headers = {"Content-Type": "application/json", "X-Trace-Id": "abc-123"}
    passed, failures, _ = evaluate_assertions(200, headers, "", 0.05, config)
    assert passed is True

    # Missing header
    passed, failures, _ = evaluate_assertions(200, {"Content-Type": "application/json"}, "", 0.05, config)
    assert passed is False
    assert any("Missing expected response header: 'x-trace-id'" in f for f in failures)

    # Value mismatch
    bad_headers = {"Content-Type": "text/html", "X-Trace-Id": "abc-123"}
    passed, failures, _ = evaluate_assertions(200, bad_headers, "", 0.05, config)
    assert passed is False
    assert any("Header 'content-type' value mismatch" in f for f in failures)


def test_evaluate_assertions_latency_sla():
    config = AssertionConfig(max_latency=0.5)

    passed, failures, sla_breached = evaluate_assertions(200, {}, "", 0.35, config)
    assert passed is True
    assert failures == []
    assert not sla_breached

    passed, failures, sla_breached = evaluate_assertions(200, {}, "", 0.85, config)
    assert passed is False
    assert sla_breached is True
    assert any("Latency SLA breached: 0.850s exceeds threshold of 0.500s" in f for f in failures)


def test_evaluate_assertions_network_failure():
    config = AssertionConfig(expect_status={200})
    passed, failures, _ = evaluate_assertions(None, None, None, 1.2, config)
    assert passed is False
    assert any("No HTTP response received" in f for f in failures)


# ==============================================================================
# 4. Network Integration (check_url_status)
# ==============================================================================

@pytest.mark.asyncio
async def test_check_url_status_with_assertions(monkeypatch):
    # Mock DNS resolution
    monkeypatch.setattr(
        "pingpanda.network.resolve_ip_and_port",
        AsyncMock(return_value="93.184.216.34:443"),
    )

    fake_response = MagicMock(spec=httpx.Response)
    fake_response.status_code = 200
    fake_response.headers = {"Content-Type": "application/json"}
    fake_response.history = []
    fake_response.text = '{"status": "ok"}'

    session = MagicMock(spec=httpx.AsyncClient)
    session.get = AsyncMock(return_value=fake_response)

    config = AssertionConfig(
        expect_status={200},
        expect_body="ok",
        expect_headers={"content-type": "application/json"},
        custom_headers={"Authorization": "Bearer token"},
        max_latency=1.0,
    )

    result = await check_url_status(
        session,
        url_id=1,
        url="https://api.example.com/health",
        assertion_config=config,
    )

    assert result.status == 200
    assert result.assertions_passed is True
    assert result.assertion_failures == []
    assert not result.sla_breached

    # Verify custom header was sent to session.get
    session.get.assert_called_once()
    _, kwargs = session.get.call_args
    assert kwargs["headers"] == {"Authorization": "Bearer token"}


@pytest.mark.asyncio
async def test_check_url_status_body_failure(monkeypatch):
    monkeypatch.setattr(
        "pingpanda.network.resolve_ip_and_port",
        AsyncMock(return_value="1.2.3.4:443"),
    )

    fake_response = MagicMock(spec=httpx.Response)
    fake_response.status_code = 200
    fake_response.headers = {}
    fake_response.history = []
    fake_response.text = '{"status": "maintenance"}'

    session = MagicMock(spec=httpx.AsyncClient)
    session.get = AsyncMock(return_value=fake_response)

    config = AssertionConfig(expect_body="healthy")
    result = await check_url_status(
        session,
        url_id=1,
        url="https://example.com/status",
        assertion_config=config,
    )

    assert result.status == 200
    assert result.assertions_passed is False
    assert any("missing expected text: 'healthy'" in f for f in result.assertion_failures)


# ==============================================================================
# 5. CLI Argument Parsing and Config Construction
# ==============================================================================

def test_cli_build_assertion_config():
    args = parse_arguments([
        "-d", "https://api.test",
        "-H", "Authorization: Bearer mytoken",
        "-H", "X-Tenant: acme",
        "--expect-status", "200,204",
        "--expect-body", "success",
        "--expect-body-regex", r'"code":\s*0',
        "--expect-header", "Content-Type: application/json",
        "--expect-header", "X-Trace-Id",
        "--max-latency", "0.25",
    ])

    config = build_assertion_config(args)
    assert config is not None
    assert config.custom_headers == {
        "Authorization": "Bearer mytoken",
        "X-Tenant": "acme",
    }
    assert config.expect_status == {200, 204}
    assert config.expect_body == "success"
    assert config.expect_body_regex is not None
    assert config.expect_body_regex.search('{"code": 0}') is not None
    assert config.expect_headers == {
        "Content-Type": "application/json",
        "X-Trace-Id": None,
    }
    assert config.max_latency == 0.25
    assert config.has_assertions is True
    assert config.requires_body is True


def test_cli_build_assertion_config_none_when_empty():
    args = parse_arguments(["-d", "https://example.com"])
    config = build_assertion_config(args)
    assert config is None


def test_cli_build_assertion_config_invalid_regex():
    args = parse_arguments(["-d", "https://test.com", "--expect-body-regex", "[invalid("])
    with pytest.raises(ValueError, match="Invalid regex"):
        build_assertion_config(args)


# ==============================================================================
# 6. Checkpoint Persistence and Resumption
# ==============================================================================

def test_checkpoint_roundtrip_with_assertions(tmp_path, make_result):
    checkpoint_file = str(tmp_path / "checkpoint.json")
    urls = ["https://service-a.com", "https://service-b.com"]

    res_a = make_result(
        url_id=0,
        url=urls[0],
        status=200,
        elapsed=0.12,
        ip_port="10.0.0.1:443",
        assertions_passed=True,
        assertion_failures=[],
        sla_breached=False,
    )
    res_b = make_result(
        url_id=1,
        url=urls[1],
        status=200,
        elapsed=0.85,
        ip_port="10.0.0.2:443",
        assertions_passed=False,
        assertion_failures=["Latency SLA breached: 0.850s exceeds 0.500s"],
        sla_breached=True,
    )

    save_checkpoint(checkpoint_file, urls, {0: res_a, 1: res_b})
    loaded = load_checkpoint(checkpoint_file, urls)

    assert len(loaded) == 2
    assert loaded[0].assertions_passed is True
    assert loaded[0].assertion_failures == []
    assert loaded[0].sla_breached is False

    assert loaded[1].assertions_passed is False
    assert loaded[1].assertion_failures == ["Latency SLA breached: 0.850s exceeds 0.500s"]
    assert loaded[1].sla_breached is True


# ==============================================================================
# 7. Reporting & Formatting Integration
# ==============================================================================

def test_format_result_line_with_assertions(make_result):
    res_pass = make_result(
        url_id=0,
        url="https://api.test/healthy",
        status=200,
        elapsed=0.045,
        ip_port="1.1.1.1:443",
        assertions_passed=True,
        assertion_failures=[],
        sla_breached=False,
    )
    line_pass = format_result_line(res_pass)
    assert "[Assertions: PASSED]" in line_pass
    assert "[SLA: BREACHED]" not in line_pass

    res_fail = make_result(
        url_id=1,
        url="https://api.test/slow",
        status=200,
        elapsed=0.650,
        ip_port="1.1.1.1:443",
        assertions_passed=False,
        assertion_failures=["Latency SLA breached", "missing expected text"],
        sla_breached=True,
    )
    line_fail = format_result_line(res_fail)
    assert "[Assertions: FAILED (Latency SLA breached; missing expected text)]" in line_fail
    assert "[SLA: BREACHED]" in line_fail


def test_extract_scan_metrics_assertion_stats(make_result):
    res1 = make_result(url_id=0, url="https://a.test", status=200, elapsed=0.1, assertions_passed=True, sla_breached=False)
    res2 = make_result(url_id=1, url="https://b.test", status=200, elapsed=0.9, assertions_passed=False, sla_breached=True)

    metrics = extract_scan_metrics([res1, res2])
    assert metrics["assertions_configured"] is True
    assert metrics["assertions_evaluated_count"] == 2
    assert metrics["assertions_passed_count"] == 1
    assert metrics["assertions_failed_count"] == 1
    assert metrics["assertions_compliance_rate"] == 50.0
    assert metrics["sla_breached_count"] == 1


def test_multi_format_reports_with_assertions(checker, make_result):
    res_pass = make_result(
        url_id=0,
        url="https://good.test",
        status=200,
        elapsed=0.05,
        ip_port="1.2.3.4:443",
        assertions_passed=True,
        assertion_failures=[],
        sla_breached=False,
    )
    res_fail = make_result(
        url_id=1,
        url="https://slow.test",
        status=200,
        elapsed=0.75,
        ip_port="1.2.3.5:443",
        assertions_passed=False,
        assertion_failures=["Latency SLA breached"],
        sla_breached=True,
    )
    status_codes = checker.classify_results({0: res_pass, 1: res_fail})

    # JSON report
    json_str = generate_json_report(status_codes)
    data = json.loads(json_str)
    assert data["metadata"]["assertions_compliance_rate_percent"] == 50.0
    assert data["metadata"]["assertions_passed_count"] == 1
    assert data["metadata"]["assertions_failed_count"] == 1
    assert data["metadata"]["sla_breached_count"] == 1
    assert data["results"][0]["assertions_passed"] is True
    assert data["results"][1]["assertions_passed"] is False
    assert data["results"][1]["sla_breached"] is True

    # CSV report
    csv_str = generate_csv_report(status_codes)
    rows = list(csv.reader(csv_str.strip().splitlines()))
    assert "assertions_passed" in rows[0]
    assert "assertion_failures" in rows[0]
    assert "sla_breached" in rows[0]
    assert rows[1][rows[0].index("assertions_passed")] == "true"
    assert rows[2][rows[0].index("assertions_passed")] == "false"
    assert rows[2][rows[0].index("sla_breached")] == "true"

    # Markdown report
    md_str = generate_markdown_report(status_codes)
    assert "Assertion Compliance" in md_str
    assert "SLA Breaches" in md_str
    assert "PASSED" in md_str
    assert "FAILED (Latency SLA breached)" in md_str

    # Plaintext report
    text_str = generate_text_report(status_codes)
    assert "[Assertions] 1/2 Passed (50.0%)" in text_str
    assert "[SLA Checks] 1 endpoint(s) breached latency threshold" in text_str
