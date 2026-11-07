"""Tests for structured multi-format reporting, percentiles, and failure diagnostics."""

from __future__ import annotations

import csv
import json
import httpx
import pytest

from pingpanda.report import (
    compute_latency_percentiles,
    extract_scan_metrics,
    generate_csv_report,
    generate_json_report,
    generate_markdown_report,
    generate_text_report,
    save_report,
)


def test_compute_latency_percentiles_empty():
    stats = compute_latency_percentiles([])
    assert stats == {
        "min": 0.0,
        "mean": 0.0,
        "p50": 0.0,
        "p95": 0.0,
        "p99": 0.0,
        "max": 0.0,
    }


def test_compute_latency_percentiles_single_element():
    stats = compute_latency_percentiles([42.5])
    assert stats["min"] == 42.5
    assert stats["mean"] == 42.5
    assert stats["p50"] == 42.5
    assert stats["p95"] == 42.5
    assert stats["p99"] == 42.5
    assert stats["max"] == 42.5


def test_compute_latency_percentiles_distribution():
    # 5 sample values: 10, 20, 30, 40, 50
    stats = compute_latency_percentiles([50.0, 10.0, 30.0, 20.0, 40.0])
    assert stats["min"] == 10.0
    assert stats["mean"] == 30.0
    assert stats["p50"] == 30.0
    assert stats["p95"] == 48.0
    assert stats["p99"] == 49.6
    assert stats["max"] == 50.0


def test_extract_scan_metrics_availability_rate_and_counts(make_result):
    results = {
        0: make_result(url_id=0, status=200, elapsed=0.02),
        1: make_result(url_id=1, status=301, elapsed=0.04),
        2: make_result(url_id=2, status=404, elapsed=0.06),
        3: make_result(
            url_id=3,
            status=None,
            elapsed=0.10,
            error_category="DNS_RESOLUTION_ERROR",
        ),
    }

    metrics = extract_scan_metrics(results)
    assert metrics["total_scanned"] == 4
    assert metrics["available_count"] == 3
    assert metrics["failed_count"] == 1
    assert metrics["availability_rate"] == 75.0
    assert metrics["error_counts"] == {"DNS_RESOLUTION_ERROR": 1}
    assert metrics["latency_stats"]["min"] == 20.0
    assert metrics["latency_stats"]["max"] == 100.0


def test_json_report_generation_structure(make_result, checker):
    results = {
        0: make_result(url_id=0, url="https://api.test/v1", status=200, elapsed=0.025),
        1: make_result(
            url_id=1,
            url="https://api.test/fail",
            status=None,
            elapsed=0.050,
            error_category="CONNECTION_TIMEOUT",
        ),
    }
    status_codes = checker.classify_results(results)

    json_str = generate_json_report(status_codes)
    data = json.loads(json_str)

    assert data["metadata"]["total_scanned"] == 2
    assert data["metadata"]["available_count"] == 1
    assert data["metadata"]["failed_count"] == 1
    assert data["metadata"]["availability_rate_percent"] == 50.0
    assert "availability_rate_definition" not in data["metadata"]
    assert "latency_definitions" not in data

    assert "p50" in data["latency_percentiles_ms"]
    assert "p95" in data["latency_percentiles_ms"]
    assert "p99" in data["latency_percentiles_ms"]
    assert data["error_diagnostics"] == {"CONNECTION_TIMEOUT": 1}

    assert len(data["results"]) == 2
    assert data["results"][0]["url"] == "https://api.test/v1"
    assert data["results"][0]["status_code"] == 200
    assert data["results"][0]["attempts"] == 1
    assert data["results"][1]["error_category"] == "CONNECTION_TIMEOUT"


def test_json_report_summary_only(make_result, checker):
    results = {0: make_result(url_id=0, status=200, elapsed=0.01)}
    status_codes = checker.classify_results(results)

    json_str = generate_json_report(status_codes, summary_only=True)
    data = json.loads(json_str)

    assert data["metadata"]["total_scanned"] == 1
    assert "results" not in data


def test_csv_report_generation(make_result, checker):
    results = {
        0: make_result(
            url_id=0,
            url="https://test.local/",
            status=200,
            elapsed=0.035,
            ip_port="127.0.0.1:443",
        ),
        1: make_result(
            url_id=1,
            url="https://bad.local/",
            status=None,
            elapsed=0.015,
            error_category="CONNECTION_REFUSED",
        ),
    }
    status_codes = checker.classify_results(results)

    csv_content = generate_csv_report(status_codes)
    reader = list(csv.reader(csv_content.strip().splitlines()))

    assert reader[0] == [
        "url_id",
        "url",
        "status_code",
        "status_label",
        "attempts",
        "elapsed_ms",
        "ip_port",
        "redirect_to",
        "redirect_ip_port",
        "error_category",
    ]
    assert reader[1][0] == "0"
    assert reader[1][1] == "https://test.local/"
    assert reader[1][2] == "200"
    assert reader[1][4] == "1"

    assert reader[2][0] == "1"
    assert reader[2][1] == "https://bad.local/"
    assert reader[2][2] == ""
    assert reader[2][3] == "Invalid"
    assert reader[2][9] == "CONNECTION_REFUSED"


def test_csv_report_summary_only(make_result, checker):
    results = {0: make_result(url_id=0, status=200, elapsed=0.02)}
    status_codes = checker.classify_results(results)

    csv_content = generate_csv_report(status_codes, summary_only=True)
    rows = dict(list(csv.reader(csv_content.strip().splitlines())))

    assert rows["metric"] == "value"
    assert rows["total_scanned"] == "1"
    assert rows["availability_rate_percent"] == "100.0%"
    assert "latency_p50_ms" in rows


def test_markdown_report_generation(make_result, checker):
    results = {
        0: make_result(url_id=0, url="https://first.test", status=200, elapsed=0.012),
        1: make_result(
            url_id=1,
            url="https://failed.test",
            status=None,
            elapsed=0.088,
            error_category="SSL_CERTIFICATE_ERROR",
        ),
    }
    status_codes = checker.classify_results(results)

    md = generate_markdown_report(status_codes)

    assert "# 🐼 PingPanda Scan Report" in md
    assert "## Summary" in md
    assert "- **Total Scanned:** 2 URLs" in md
    assert "- **Availability Rate:** 50.0%" in md
    assert "## Latency Distribution" in md
    assert "| **Min** |" in md
    assert "| **p50 (Median)** |" in md
    assert "| **p95** |" in md
    assert "| **p99** |" in md
    assert "| **Max** |" in md
    assert "## Failure Diagnostics" in md
    assert "`SSL_CERTIFICATE_ERROR`" in md
    assert "## Detailed Results" in md
    assert "https://first.test" in md


def test_markdown_report_summary_only(make_result, checker):
    results = {0: make_result(url_id=0, status=200, elapsed=0.01)}
    status_codes = checker.classify_results(results)

    md = generate_markdown_report(status_codes, summary_only=True)

    assert "# 🐼 PingPanda Scan Report" in md
    assert "## Detailed Results" not in md


def test_save_report_prints_path_confirmation(make_result, checker, tmp_path, capsys):
    results = {0: make_result(status=200, url="https://example.com")}
    status_codes = checker.classify_results(results)

    json_path = tmp_path / "out.json"
    save_report(status_codes, str(json_path), format="json")
    out = capsys.readouterr().out

    assert f"[Report] Saved JSON report to {json_path}" in out
    assert json_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["metadata"]["total_scanned"] == 1


def test_save_report_supports_all_formats(make_result, checker, tmp_path):
    results = {0: make_result(status=200, url="https://example.com")}
    status_codes = checker.classify_results(results)

    for fmt, ext in (
        ("json", "json"),
        ("csv", "csv"),
        ("markdown", "md"),
        ("text", "txt"),
    ):
        file_path = tmp_path / f"report.{ext}"
        save_report(status_codes, str(file_path), format=fmt)
        assert file_path.exists()
        assert len(file_path.read_text(encoding="utf-8")) > 0


def test_save_report_rejects_unsupported_format(make_result, checker, tmp_path):
    results = {0: make_result(status=200)}
    status_codes = checker.classify_results(results)

    with pytest.raises(ValueError, match="Unsupported report format"):
        save_report(status_codes, str(tmp_path / "report.xml"), format="xml")


def test_cli_argument_parsing_format_and_summary_only(checker):
    args = checker.parse_arguments(["--format", "json", "--summary-only"])
    assert args.format == "json"
    assert args.summary_only is True


def test_cli_argument_parsing_format_default(checker):
    args = checker.parse_arguments([])
    assert args.format == "text"
    assert args.summary_only is False


async def test_cli_main_exports_json(checker, mock_transport, fake_dns, tmp_path, capsys):
    def handler(request):
        return httpx.Response(200)

    mock_transport(handler)
    target = tmp_path / "results.json"
    await checker.main(["-d", "https://example.com", "--format", "json", "-o", str(target)])

    out = capsys.readouterr().out
    assert f"[Report] Saved JSON report to {target}" in out
    assert target.exists()

    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["metadata"]["total_scanned"] == 1
    assert data["metadata"]["availability_rate_percent"] == 100.0


async def test_cli_main_exports_csv(checker, mock_transport, fake_dns, tmp_path):
    def handler(request):
        return httpx.Response(200)

    mock_transport(handler)
    target = tmp_path / "results.csv"
    await checker.main(["-d", "https://example.com", "--format", "csv", "-o", str(target)])

    assert target.exists()
    content = target.read_text(encoding="utf-8")
    assert "https://example.com" in content
    assert "200" in content


async def test_cli_main_exports_markdown(checker, mock_transport, fake_dns, tmp_path):
    def handler(request):
        return httpx.Response(200)

    mock_transport(handler)
    target = tmp_path / "results.md"
    await checker.main(["-d", "https://example.com", "--format", "markdown", "-o", str(target)])

    assert target.exists()
    content = target.read_text(encoding="utf-8")
    assert "# 🐼 PingPanda Scan Report" in content
    assert "Availability Rate" in content
    assert "Latency Distribution" in content


async def test_network_failure_categorization_refused(checker):
    def handler(request):
        raise httpx.ConnectError("connection refused")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as session:
        result = await checker.check_url_status(session, 0, "https://refused.test")

    assert result.status is None
    assert result.error_category == "CONNECTION_REFUSED"


async def test_network_failure_categorization_dns(checker):
    def handler(request):
        raise httpx.ConnectError("[Errno -2] Name or service not known gaierror")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as session:
        result = await checker.check_url_status(session, 0, "https://dnsfail.test")

    assert result.status is None
    assert result.error_category == "DNS_RESOLUTION_ERROR"


async def test_network_failure_categorization_ssl(checker):
    def handler(request):
        raise httpx.RequestError("SSL: CERTIFICATE_VERIFY_FAILED certificate has expired")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as session:
        result = await checker.check_url_status(session, 0, "https://sslbad.test")

    assert result.status is None
    assert result.error_category == "SSL_CERTIFICATE_ERROR"
