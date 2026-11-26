"""Continuous watch mode with cross-cycle uptime tracking and regression alerts."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import csv
import datetime
import io
import json
import time
from dataclasses import dataclass, field
from typing import Any

from colorama import Fore, Style

from pingpanda.cancellation import CancellationToken, ScanCancelled
from pingpanda.models import UrlResult
from pingpanda.network import (
    DEFAULT_MAX_CONCURRENT,
    DEFAULT_RETRIES,
    DEFAULT_RETRY_DELAY_SECONDS,
    check_all,
)
from pingpanda.report import compute_latency_percentiles


@dataclass
class WatchConfig:
    """Configuration for continuous URL watch monitoring."""

    interval_seconds: float
    max_cycles: int | None = None
    changes_only: bool = False


@dataclass
class TransitionEvent:
    """A state transition detected between consecutive watch cycles."""

    cycle: int
    timestamp: str
    url_id: int
    url: str
    kind: str  # REGRESSION, RECOVERED, SLA BREACH, ASSERTION FAILED, SSL CHANGE, STATUS CHANGE
    previous_summary: str
    current_summary: str
    uptime_pct: float
    consecutive_failures: int


@dataclass
class UrlWatchStats:
    """Aggregated monitoring statistics for a single URL across watch cycles."""

    url_id: int
    url: str
    checks: int = 0
    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    max_consecutive_failures: int = 0
    transitions: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    latest_result: UrlResult | None = None
    previous_healthy: bool | None = None
    previous_status: int | None = None
    previous_sla_breached: bool | None = None
    previous_assertions_passed: bool | None = None
    previous_ssl_status: str | None = None

    @property
    def uptime_pct(self) -> float:
        if self.checks == 0:
            return 0.0
        return round((self.successes / self.checks) * 100.0, 2)

    @property
    def latency_percentiles(self) -> dict[str, float]:
        return compute_latency_percentiles(self.latencies_ms)


def is_result_healthy(result: UrlResult) -> bool:
    """Return True if status, assertions, SLA, and SSL checks all succeeded."""
    if result.status is None or not (100 <= result.status < 400):
        return False
    if result.assertions_passed is False:
        return False
    if result.sla_breached:
        return False
    ssl_info = getattr(result, "ssl_info", None)
    if ssl_info is not None and ssl_info.is_https and ssl_info.valid is False:
        return False
    return True


def _describe_result_state(result: UrlResult) -> str:
    """Format a compact single-token summary of a result's status and checks."""
    if result.status is None:
        return f"Invalid ({result.error_category})" if result.error_category else "Invalid"

    parts = [str(result.status)]
    if result.sla_breached:
        parts.append("SLA breached")
    if result.assertions_passed is False:
        parts.append("Assertions failed")
    ssl_info = getattr(result, "ssl_info", None)
    if ssl_info is not None and ssl_info.is_https and ssl_info.status in ("expired", "error", "warning"):
        parts.append(f"SSL {ssl_info.status}")
    return " / ".join(parts)


class WatchTracker:
    """Tracks per-URL uptime, latency history, and transitions across watch cycles."""

    def __init__(self, urls: list[str]) -> None:
        self.urls = list(urls)
        self.cycle_count = 0
        self.urls_stats: dict[int, UrlWatchStats] = {
            idx: UrlWatchStats(url_id=idx, url=url)
            for idx, url in enumerate(urls)
        }
        self.events: list[TransitionEvent] = []
        self.cycle_summaries: list[dict[str, Any]] = []

    def record_cycle(
        self,
        cycle: int,
        results: dict[int, UrlResult],
        timestamp: str | None = None,
    ) -> list[TransitionEvent]:
        """Record one completed scan cycle and return transitions detected."""
        ts = timestamp or datetime.datetime.now().strftime("%H:%M:%S")
        self.cycle_count = max(self.cycle_count, cycle)
        cycle_events: list[TransitionEvent] = []
        ok_count = 0
        fail_count = 0
        cycle_latencies: list[float] = []

        for url_id, result in sorted(results.items()):
            stats = self.urls_stats.setdefault(
                url_id, UrlWatchStats(url_id=url_id, url=result.url)
            )
            healthy = is_result_healthy(result)
            stats.checks += 1
            if healthy:
                stats.successes += 1
                stats.consecutive_failures = 0
                ok_count += 1
            else:
                stats.failures += 1
                stats.consecutive_failures += 1
                stats.max_consecutive_failures = max(
                    stats.max_consecutive_failures, stats.consecutive_failures
                )
                fail_count += 1

            stats.latencies_ms.append(result.elapsed_ms)
            cycle_latencies.append(result.elapsed_ms)

            ssl_info = getattr(result, "ssl_info", None)
            ssl_status = ssl_info.status if (ssl_info and ssl_info.is_https) else None

            event_kind = self._detect_transition(stats, result, healthy, ssl_status)
            if event_kind is not None and stats.latest_result is not None:
                stats.transitions += 1
                event = TransitionEvent(
                    cycle=cycle,
                    timestamp=ts,
                    url_id=url_id,
                    url=result.url,
                    kind=event_kind,
                    previous_summary=_describe_result_state(stats.latest_result),
                    current_summary=_describe_result_state(result),
                    uptime_pct=stats.uptime_pct,
                    consecutive_failures=stats.consecutive_failures,
                )
                cycle_events.append(event)
                self.events.append(event)

            stats.latest_result = result
            stats.previous_healthy = healthy
            stats.previous_status = result.status
            stats.previous_sla_breached = result.sla_breached
            stats.previous_assertions_passed = result.assertions_passed
            stats.previous_ssl_status = ssl_status

        mean_ms = round(sum(cycle_latencies) / len(cycle_latencies), 2) if cycle_latencies else 0.0
        self.cycle_summaries.append(
            {
                "cycle": cycle,
                "timestamp": ts,
                "checked": len(results),
                "ok": ok_count,
                "failed": fail_count,
                "mean_ms": mean_ms,
                "transitions": len(cycle_events),
            }
        )
        return cycle_events

    @staticmethod
    def _detect_transition(
        stats: UrlWatchStats,
        result: UrlResult,
        healthy: bool,
        ssl_status: str | None,
    ) -> str | None:
        if stats.previous_healthy is None:
            return None

        if stats.previous_healthy and not healthy:
            if result.status is not None and 100 <= result.status < 400:
                if result.sla_breached:
                    return "SLA BREACH"
                if result.assertions_passed is False:
                    return "ASSERTION FAILED"
                if ssl_status in ("expired", "error"):
                    return "SSL CHANGE"
            return "REGRESSION"

        if not stats.previous_healthy and healthy:
            return "RECOVERED"

        if stats.previous_ssl_status != ssl_status and ssl_status is not None:
            return "SSL CHANGE"

        if stats.previous_status != result.status:
            return "STATUS CHANGE"

        return None

    def build_summary_data(self) -> dict[str, Any]:
        """Build structured multi-cycle watch summary metrics for rendering and export."""
        url_entries: list[dict[str, Any]] = []
        total_checks = 0
        total_successes = 0

        for url_id in sorted(self.urls_stats):
            stats = self.urls_stats[url_id]
            total_checks += stats.checks
            total_successes += stats.successes
            latest_label = (
                _describe_result_state(stats.latest_result)
                if stats.latest_result is not None
                else "Pending"
            )
            url_entries.append(
                {
                    "url_id": stats.url_id,
                    "url": stats.url,
                    "checks": stats.checks,
                    "successes": stats.successes,
                    "failures": stats.failures,
                    "uptime_pct": stats.uptime_pct,
                    "transitions": stats.transitions,
                    "max_consecutive_failures": stats.max_consecutive_failures,
                    "latency_ms": stats.latency_percentiles,
                    "latest_status": latest_label,
                }
            )

        overall_uptime = round((total_successes / total_checks) * 100.0, 2) if total_checks else 0.0
        return {
            "cycles_completed": self.cycle_count,
            "total_checks": total_checks,
            "overall_uptime_pct": overall_uptime,
            "total_transitions": len(self.events),
            "urls": url_entries,
            "events": [
                {
                    "cycle": ev.cycle,
                    "timestamp": ev.timestamp,
                    "url": ev.url,
                    "kind": ev.kind,
                    "from": ev.previous_summary,
                    "to": ev.current_summary,
                    "uptime_pct": ev.uptime_pct,
                }
                for ev in self.events
            ],
            "cycles": list(self.cycle_summaries),
        }


def format_cycle_output(
    cycle: int,
    timestamp: str,
    summary_entry: dict[str, Any],
    events: list[TransitionEvent],
    *,
    changes_only: bool = False,
    no_colour: bool = False,
) -> str:
    """Format terminal output for a single watch cycle."""
    if changes_only and cycle > 1 and not events:
        return ""

    lines: list[str] = []
    hdr = f"--- Cycle #{cycle} ({timestamp}) ---"
    lines.append(hdr if no_colour else f"{Fore.CYAN}{hdr}{Style.RESET_ALL}")

    for ev in events:
        streak = f", streak: {ev.consecutive_failures} fail" if ev.consecutive_failures else ""
        msg = (
            f"[{ev.kind}] {ev.url}  {ev.previous_summary} -> {ev.current_summary} "
            f"(Uptime: {ev.uptime_pct:.1f}%{streak})"
        )
        if not no_colour:
            colour = Fore.GREEN if ev.kind == "RECOVERED" else Fore.RED
            msg = f"{colour}{msg}{Style.RESET_ALL}"
        lines.append(msg)

    stats_line = (
        f"OK: {summary_entry['ok']} | Failed: {summary_entry['failed']} | "
        f"Mean: {summary_entry['mean_ms']:.2f} ms"
    )
    lines.append(stats_line)
    return "\n".join(lines)


def format_watch_summary(summary_data: dict[str, Any], *, no_colour: bool = False) -> str:
    """Format the final multi-cycle watch summary table for terminal output."""
    cycles = summary_data["cycles_completed"]
    lines: list[str] = []
    title = f"===== WATCH SUMMARY ({cycles} cycle{'s' if cycles != 1 else ''}) ====="
    lines.append("")
    lines.append(title if no_colour else f"{Fore.CYAN}{title}{Style.RESET_ALL}")
    lines.append(
        f"Overall Uptime: {summary_data['overall_uptime_pct']:.2f}% | "
        f"Total Checks: {summary_data['total_checks']} | "
        f"Transitions: {summary_data['total_transitions']}"
    )

    for entry in summary_data["urls"]:
        lat = entry["latency_ms"]
        lines.append(
            f"- {entry['url']} | Checks: {entry['checks']} | "
            f"Uptime: {entry['uptime_pct']:.1f}% | Transitions: {entry['transitions']} | "
            f"Mean: {lat['mean']:.2f} ms | p95: {lat['p95']:.2f} ms | "
            f"Latest: {entry['latest_status']}"
        )
    return "\n".join(lines)


def generate_watch_json_report(summary_data: dict[str, Any]) -> str:
    """Serialize watch summary data as formatted JSON."""
    return json.dumps(summary_data, indent=2) + "\n"


def generate_watch_csv_report(summary_data: dict[str, Any]) -> str:
    """Serialize per-URL watch statistics as RFC 4180 CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        [
            "url_id",
            "url",
            "checks",
            "successes",
            "failures",
            "uptime_pct",
            "transitions",
            "max_consecutive_failures",
            "mean_ms",
            "p95_ms",
            "latest_status",
        ]
    )
    for entry in summary_data["urls"]:
        lat = entry["latency_ms"]
        writer.writerow(
            [
                entry["url_id"],
                entry["url"],
                entry["checks"],
                entry["successes"],
                entry["failures"],
                entry["uptime_pct"],
                entry["transitions"],
                entry["max_consecutive_failures"],
                lat["mean"],
                lat["p95"],
                entry["latest_status"],
            ]
        )
    return buf.getvalue()


def generate_watch_markdown_report(summary_data: dict[str, Any]) -> str:
    """Generate a Markdown summary report for a completed watch session."""
    lines = [
        "# PingPanda Watch Summary",
        "",
        f"- **Cycles Completed:** {summary_data['cycles_completed']}",
        f"- **Total Checks:** {summary_data['total_checks']}",
        f"- **Overall Uptime:** {summary_data['overall_uptime_pct']:.2f}%",
        f"- **Transitions Detected:** {summary_data['total_transitions']}",
        "",
        "## Endpoint Reliability",
        "",
        "| URL | Checks | Uptime | Transitions | Mean (ms) | p95 (ms) | Latest |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for entry in summary_data["urls"]:
        lat = entry["latency_ms"]
        lines.append(
            f"| {entry['url']} | {entry['checks']} | {entry['uptime_pct']:.1f}% | "
            f"{entry['transitions']} | {lat['mean']:.2f} | {lat['p95']:.2f} | "
            f"{entry['latest_status']} |"
        )
    return "\n".join(lines) + "\n"


_WATCH_EXPORTERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "json": generate_watch_json_report,
    "csv": generate_watch_csv_report,
    "markdown": generate_watch_markdown_report,
}


def save_watch_report(
    summary_data: dict[str, Any],
    output_path: str,
    *,
    format: str = "text",
) -> None:
    """Write the watch summary report to disk in the requested format."""
    exporter = _WATCH_EXPORTERS.get(format)
    if exporter is not None:
        content = exporter(summary_data)
    else:
        content = format_watch_summary(summary_data, no_colour=True) + "\n"

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(content)


async def _wait_for_next_interval(
    interval_seconds: float,
    cancellation_token: CancellationToken | None,
    sleep_fn: Callable[[float], Any],
) -> bool:
    """Sleep up to interval_seconds while checking for cancellation.

    Returns True if interrupted by cancellation, False if full interval elapsed.
    """
    if interval_seconds <= 0:
        return bool(cancellation_token and cancellation_token.cancelled)

    deadline = time.monotonic() + interval_seconds
    while True:
        if cancellation_token is not None and cancellation_token.cancelled:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        await sleep_fn(min(0.2, remaining))


async def run_watch(
    urls: list[str],
    watch_config: WatchConfig,
    *,
    max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    show_progress: bool = True,
    max_retries: int = DEFAULT_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY_SECONDS,
    assertion_config: Any = None,
    ssl_config: Any = None,
    cancellation_token: CancellationToken | None = None,
    no_colour: bool = False,
    check_fn: Callable[..., Any] = check_all,
    sleep_fn: Callable[[float], Any] = asyncio.sleep,
    printer: Callable[[str], None] = print,
    now_fn: Callable[[], str] | None = None,
) -> tuple[WatchTracker, bool]:
    """Run periodic URL monitoring cycles until max_cycles or cancellation."""
    tracker = WatchTracker(urls)
    interrupted = False

    if not no_colour:
        printer(
            f"{Fore.CYAN}[Watch] Monitoring {len(urls)} URL(s) every "
            f"{watch_config.interval_seconds:g}s (Press Ctrl+C to stop){Style.RESET_ALL}"
        )
    else:
        printer(
            f"[Watch] Monitoring {len(urls)} URL(s) every "
            f"{watch_config.interval_seconds:g}s (Press Ctrl+C to stop)"
        )

    cycle = 0
    while True:
        if cancellation_token is not None and cancellation_token.cancelled:
            interrupted = True
            break

        if watch_config.max_cycles is not None and cycle >= watch_config.max_cycles:
            break

        cycle += 1
        timestamp = now_fn() if now_fn is not None else datetime.datetime.now().strftime("%H:%M:%S")

        try:
            results = await check_fn(
                urls,
                initial_results={},
                on_result=None,
                max_concurrent=max_concurrent,
                show_progress=show_progress,
                max_retries=max_retries,
                retry_delay=retry_delay,
                assertion_config=assertion_config,
                cancellation_token=cancellation_token,
                ssl_config=ssl_config,
            )
        except ScanCancelled as exc:
            interrupted = True
            if exc.results:
                events = tracker.record_cycle(cycle, exc.results, timestamp=timestamp)
                block = format_cycle_output(
                    cycle,
                    timestamp,
                    tracker.cycle_summaries[-1],
                    events,
                    changes_only=watch_config.changes_only,
                    no_colour=no_colour,
                )
                if block:
                    printer(block)
            break

        events = tracker.record_cycle(cycle, results, timestamp=timestamp)
        block = format_cycle_output(
            cycle,
            timestamp,
            tracker.cycle_summaries[-1],
            events,
            changes_only=watch_config.changes_only,
            no_colour=no_colour,
        )
        if block:
            printer(block)

        if watch_config.max_cycles is not None and cycle >= watch_config.max_cycles:
            break

        if await _wait_for_next_interval(
            watch_config.interval_seconds, cancellation_token, sleep_fn
        ):
            interrupted = True
            break

    return tracker, interrupted
