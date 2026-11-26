"""Tests for continuous watch mode, uptime tracking, and regression alerts."""

import json
from unittest.mock import patch

import pytest

from pingpanda.cancellation import CancellationToken, ScanCancelled
from pingpanda.cli import build_watch_config, main, parse_arguments
from pingpanda.models import UrlResult
from pingpanda.ssl_check import SslCertificateInfo
from pingpanda.watch import (
    WatchConfig,
    WatchTracker,
    format_cycle_output,
    format_watch_summary,
    generate_watch_csv_report,
    generate_watch_json_report,
    generate_watch_markdown_report,
    is_result_healthy,
    run_watch,
    save_watch_report,
)


def _make_result(
    url_id: int,
    url: str,
    status: int | None = 200,
    elapsed: float = 0.1,
    *,
    error_category: str | None = None,
    assertions_passed: bool | None = None,
    sla_breached: bool = False,
    ssl_info: SslCertificateInfo | None = None,
) -> UrlResult:
    return UrlResult(
        url_id=url_id,
        url=url,
        status=status,
        elapsed=elapsed,
        redirect_to=None,
        ip_port="93.184.216.34:443",
        redirect_ip_port=None,
        error_category=error_category,
        assertions_passed=assertions_passed,
        sla_breached=sla_breached,
        ssl_info=ssl_info,
    )


def test_cli_watch_arguments_and_validation():
    args_off = parse_arguments(["-d", "https://example.com"])
    assert build_watch_config(args_off) is None

    args_on = parse_arguments(
        ["-d", "https://example.com", "--watch", "5", "--watch-cycles", "3", "--watch-changes-only"]
    )
    cfg = build_watch_config(args_on)
    assert cfg is not None
    assert cfg.interval_seconds == 5.0
    assert cfg.max_cycles == 3
    assert cfg.changes_only is True

    args_bad = parse_arguments(["-d", "https://example.com", "--watch-cycles", "2"])
    with pytest.raises(ValueError, match="require --watch"):
        build_watch_config(args_bad)

    for bad_val in ("0", "-2", "nan", "inf", "abc"):
        with pytest.raises(SystemExit):
            parse_arguments(["-d", "https://example.com", "--watch", bad_val])


def test_is_result_healthy_variants():
    assert is_result_healthy(_make_result(0, "https://a.com", 200)) is True
    assert is_result_healthy(_make_result(0, "https://a.com", 301)) is True
    assert is_result_healthy(_make_result(0, "https://a.com", 503)) is False
    assert is_result_healthy(_make_result(0, "https://a.com", None)) is False
    assert is_result_healthy(_make_result(0, "https://a.com", 200, assertions_passed=False)) is False
    assert is_result_healthy(_make_result(0, "https://a.com", 200, sla_breached=True)) is False

    bad_ssl = SslCertificateInfo(is_https=True, valid=False, status="expired")
    assert is_result_healthy(_make_result(0, "https://a.com", 200, ssl_info=bad_ssl)) is False


def test_watch_tracker_transitions_and_uptime():
    urls = ["https://api.example.com", "https://cdn.example.com"]
    tracker = WatchTracker(urls)

    # Cycle 1: baseline
    ev1 = tracker.record_cycle(
        1,
        {
            0: _make_result(0, urls[0], 200, 0.10),
            1: _make_result(1, urls[1], 200, 0.05),
        },
        timestamp="09:00:00",
    )
    assert ev1 == []

    # Cycle 2: URL 0 regresses to 503
    ev2 = tracker.record_cycle(
        2,
        {
            0: _make_result(0, urls[0], 503, 0.20),
            1: _make_result(1, urls[1], 200, 0.05),
        },
        timestamp="09:00:10",
    )
    assert len(ev2) == 1
    assert ev2[0].kind == "REGRESSION"
    assert ev2[0].consecutive_failures == 1
    assert ev2[0].uptime_pct == 50.0

    # Cycle 3: URL 0 recovers, URL 1 breaches SLA
    ev3 = tracker.record_cycle(
        3,
        {
            0: _make_result(0, urls[0], 200, 0.15),
            1: _make_result(1, urls[1], 200, 1.50, sla_breached=True),
        },
        timestamp="09:00:20",
    )
    kinds = {e.url_id: e.kind for e in ev3}
    assert kinds == {0: "RECOVERED", 1: "SLA BREACH"}

    summary = tracker.build_summary_data()
    assert summary["cycles_completed"] == 3
    assert summary["total_checks"] == 6
    assert summary["total_transitions"] == 3
    assert summary["urls"][0]["uptime_pct"] == pytest.approx(66.67, abs=0.01)
    assert summary["urls"][0]["max_consecutive_failures"] == 1
    assert summary["urls"][1]["uptime_pct"] == pytest.approx(66.67, abs=0.01)


def test_watch_tracker_ssl_and_status_changes():
    urls = ["https://ssl.example.com"]
    tracker = WatchTracker(urls)

    ssl_ok = SslCertificateInfo(is_https=True, valid=True, status="valid")
    ssl_warn = SslCertificateInfo(is_https=True, valid=True, status="warning")

    tracker.record_cycle(1, {0: _make_result(0, urls[0], 200, ssl_info=ssl_ok)}, timestamp="09:00:00")
    ev_ssl = tracker.record_cycle(2, {0: _make_result(0, urls[0], 200, ssl_info=ssl_warn)}, timestamp="09:00:10")
    assert len(ev_ssl) == 1
    assert ev_ssl[0].kind == "SSL CHANGE"

    ev_redir = tracker.record_cycle(3, {0: _make_result(0, urls[0], 301, ssl_info=ssl_warn)}, timestamp="09:00:20")
    assert len(ev_redir) == 1
    assert ev_redir[0].kind == "STATUS CHANGE"


@pytest.mark.asyncio
async def test_run_watch_bounded_cycles_and_changes_only():
    urls = ["https://example.com"]
    outputs: list[str] = []
    call_count = 0

    async def fake_check_all(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        status = 500 if call_count == 3 else 200
        return {0: _make_result(0, urls[0], status, 0.05)}

    async def fast_sleep(_sec):
        return None

    tracker, interrupted = await run_watch(
        urls,
        WatchConfig(interval_seconds=1.0, max_cycles=3, changes_only=True),
        no_colour=True,
        show_progress=False,
        check_fn=fake_check_all,
        sleep_fn=fast_sleep,
        printer=outputs.append,
        now_fn=lambda: "12:00:00",
    )

    assert interrupted is False
    assert call_count == 3
    assert tracker.cycle_count == 3
    # Header + Cycle #1 + Cycle #3 (Cycle #2 skipped by changes_only)
    assert len(outputs) == 3
    assert "Cycle #1" in outputs[1]
    assert "Cycle #2" not in "\n".join(outputs)
    assert "[REGRESSION]" in outputs[2]


@pytest.mark.asyncio
async def test_run_watch_cancellation_during_sleep_and_scan():
    urls = ["https://example.com"]
    token = CancellationToken()

    async def fake_check_cancel_after_one(*args, **kwargs):
        token.cancel()
        return {0: _make_result(0, urls[0], 200, 0.05)}

    async def fast_sleep(_sec):
        return None

    tracker, interrupted = await run_watch(
        urls,
        WatchConfig(interval_seconds=10.0, max_cycles=5),
        cancellation_token=token,
        no_colour=True,
        show_progress=False,
        check_fn=fake_check_cancel_after_one,
        sleep_fn=fast_sleep,
        printer=lambda _s: None,
    )
    assert interrupted is True
    assert tracker.cycle_count == 1

    # Simulate ScanCancelled raised mid-cycle
    async def fake_scan_cancelled(*args, **kwargs):
        raise ScanCancelled({0: _make_result(0, urls[0], 200, 0.05)})

    tracker2, interrupted2 = await run_watch(
        urls,
        WatchConfig(interval_seconds=10.0, max_cycles=5),
        cancellation_token=CancellationToken(),
        no_colour=True,
        show_progress=False,
        check_fn=fake_scan_cancelled,
        sleep_fn=fast_sleep,
        printer=lambda _s: None,
    )
    assert interrupted2 is True
    assert tracker2.cycle_count == 1


def test_watch_report_formats_and_save(tmp_path):
    tracker = WatchTracker(["https://example.com"])
    tracker.record_cycle(1, {0: _make_result(0, "https://example.com", 200, 0.12)}, timestamp="10:00:00")
    summary = tracker.build_summary_data()

    text_out = format_watch_summary(summary, no_colour=True)
    assert "WATCH SUMMARY (1 cycle)" in text_out
    assert "100.0%" in text_out

    json_parsed = json.loads(generate_watch_json_report(summary))
    assert json_parsed["cycles_completed"] == 1
    assert json_parsed["urls"][0]["uptime_pct"] == 100.0

    csv_out = generate_watch_csv_report(summary)
    assert "url_id,url,checks,successes" in csv_out
    assert "https://example.com" in csv_out

    md_out = generate_watch_markdown_report(summary)
    assert "# PingPanda Watch Summary" in md_out
    assert "| https://example.com |" in md_out

    out_file = tmp_path / "watch.json"
    save_watch_report(summary, str(out_file), format="json")
    assert json.loads(out_file.read_text(encoding="utf-8"))["overall_uptime_pct"] == 100.0

    cycle_block = format_cycle_output(
        1, "10:00:00", tracker.cycle_summaries[0], [], changes_only=False, no_colour=True
    )
    assert "Cycle #1" in cycle_block


@pytest.mark.asyncio
async def test_cli_main_watch_end_to_end(tmp_path):
    out_json = tmp_path / "watch_out.json"

    async def fake_check_all(urls, **_kwargs):
        return {0: _make_result(0, urls[0], 200, 0.08)}

    with patch("pingpanda.watch.check_all", side_effect=fake_check_all):
        code = await main(
            [
                "-d",
                "https://example.com",
                "--watch",
                "0.01",
                "--watch-cycles",
                "2",
                "--quiet",
                "--no-colour",
                "--format",
                "json",
                "-o",
                str(out_json),
            ]
        )

    assert code == 0
    saved = json.loads(out_json.read_text(encoding="utf-8"))
    assert saved["cycles_completed"] == 2
    assert saved["total_checks"] == 2
    assert saved["overall_uptime_pct"] == 100.0
