"""Turning the results of the checks into the report."""

from __future__ import annotations

import csv
import io
import json
import math
from typing import Any, Sequence

from colorama import Fore, Style

from pingpanda.constants import COLORS, STATUS_GROUPS
from pingpanda.models import UrlResult


# Group the results by their HTTP status class
def classify_results(results: dict[int, UrlResult]) -> dict[str, list[UrlResult]]:
    status_codes: dict[str, list[UrlResult]] = {group: [] for group in STATUS_GROUPS}
    for result in results.values():
        if result.status is None:
            status_codes["Invalid"].append(result)
            continue
        status_group = f"{result.status // 100}xx"
        status_group = {"4xx": "5xx", "5xx": "4xx"}.get(status_group, status_group)
        status_codes.setdefault(status_group, []).append(result)
    return status_codes


# Build the single line that describes one checked URL
def format_result_line(result: UrlResult) -> str:
    redirect_str = (
        f"[Redirect: {result.redirect_to} ({result.redirect_ip_port})]"
        if result.redirect_to
        else "[Redirect: None]"
    )
    assertion_str = ""
    if result.assertions_passed is True:
        assertion_str = " [Assertions: PASSED]"
    elif result.assertions_passed is False:
        fail_desc = "; ".join(result.assertion_failures) if result.assertion_failures else "FAILED"
        assertion_str = f" [Assertions: FAILED ({fail_desc})]"

    sla_str = " [SLA: BREACHED]" if result.sla_breached else ""

    return (
        f"[Status: {result.status_label}] [Attempts: {result.attempts}] "
        f"[Time: {result.elapsed:.3f} ms] "
        f"[IP: {result.ip_port}] {result.url} {redirect_str}{assertion_str}{sla_str}"
    )


# One line summary of a whole run
def summarize(status_codes: dict[str, list[UrlResult]]) -> str:
    parts = [f"Checked: {sum(len(group) for group in status_codes.values())}"]
    for group in ("1xx", "2xx", "3xx", "4xx", "5xx"):
        parts.append(f"{group}: {len(status_codes[group])}")
    parts.append(f"Failed: {len(status_codes['4xx'])}")
    return " | ".join(parts)


def compute_latency_percentiles(latencies_ms: Sequence[float]) -> dict[str, float]:
    """Calculate min, mean, p50, p95, p99, and max latencies in milliseconds.

    Safely handles empty datasets, single-element lists, and duplicate values.
    """
    if not latencies_ms:
        return {
            "min": 0.0,
            "mean": 0.0,
            "p50": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "max": 0.0,
        }

    sorted_vals = sorted(latencies_ms)
    n = len(sorted_vals)

    def percentile(p: float) -> float:
        if n == 1:
            return sorted_vals[0]
        k = (n - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_vals[int(k)]
        d0 = sorted_vals[f] * (c - k)
        d1 = sorted_vals[c] * (k - f)
        return d0 + d1

    return {
        "min": round(sorted_vals[0], 2),
        "mean": round(sum(sorted_vals) / n, 2),
        "p50": round(percentile(50.0), 2),
        "p95": round(percentile(95.0), 2),
        "p99": round(percentile(99.0), 2),
        "max": round(sorted_vals[-1], 2),
    }


def extract_scan_metrics(
    results_or_status_codes: dict[str, list[UrlResult]]
    | dict[int, UrlResult]
    | Sequence[UrlResult],
) -> dict[str, Any]:
    """Extract scan statistics, availability rate, latency percentiles, and error diagnostics."""
    if isinstance(results_or_status_codes, dict):
        first_val = next(iter(results_or_status_codes.values()), None)
        if isinstance(first_val, list):
            # dict of status_group -> list[UrlResult]
            result_list = [
                r for sublist in results_or_status_codes.values() for r in sublist
            ]
        else:
            # dict of url_id -> UrlResult
            result_list = list(results_or_status_codes.values())  # type: ignore[arg-type]
    else:
        result_list = list(results_or_status_codes)

    total_scanned = len(result_list)
    available_results = [r for r in result_list if r.status is not None]
    available_count = len(available_results)
    failed_count = total_scanned - available_count

    availability_rate = (
        round((available_count / total_scanned) * 100.0, 2)
        if total_scanned > 0
        else 0.0
    )

    latencies_ms = [r.elapsed * 1000.0 for r in result_list]
    latency_stats = compute_latency_percentiles(latencies_ms)

    status_counts = {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "Invalid": 0}
    error_counts: dict[str, int] = {}

    for r in result_list:
        if r.status is None:
            status_counts["Invalid"] += 1
            cat = getattr(r, "error_category", None) or "UNSPECIFIED_FAILURE"
            error_counts[cat] = error_counts.get(cat, 0) + 1
        else:
            group = f"{r.status // 100}xx"
            status_counts[group] = status_counts.get(group, 0) + 1

    evaluated_assertions = [r for r in result_list if r.assertions_passed is not None]
    assertions_configured = len(evaluated_assertions) > 0
    passed_assertions = [r for r in evaluated_assertions if r.assertions_passed]
    assertions_passed_count = len(passed_assertions)
    assertions_failed_count = len(evaluated_assertions) - assertions_passed_count
    assertions_compliance_rate = (
        round((assertions_passed_count / len(evaluated_assertions)) * 100.0, 2)
        if evaluated_assertions
        else 0.0
    )
    sla_breached_count = sum(1 for r in result_list if r.sla_breached)

    return {
        "total_scanned": total_scanned,
        "available_count": available_count,
        "failed_count": failed_count,
        "availability_rate": availability_rate,
        "status_counts": status_counts,
        "error_counts": error_counts,
        "latency_stats": latency_stats,
        "assertions_configured": assertions_configured,
        "assertions_evaluated_count": len(evaluated_assertions),
        "assertions_passed_count": assertions_passed_count,
        "assertions_failed_count": assertions_failed_count,
        "assertions_compliance_rate": assertions_compliance_rate,
        "sla_breached_count": sla_breached_count,
    }


def generate_json_report(
    status_codes: dict[str, list[UrlResult]],
    summary_only: bool = False,
) -> str:
    """Generate structured JSON report string."""
    all_results = [r for sublist in status_codes.values() for r in sublist]
    all_results.sort(key=lambda r: getattr(r, "url_id", 0))

    metrics = extract_scan_metrics(all_results)

    data: dict[str, Any] = {
        "metadata": {
            "total_scanned": metrics["total_scanned"],
            "available_count": metrics["available_count"],
            "failed_count": metrics["failed_count"],
            "availability_rate_percent": metrics["availability_rate"],
        },
        "status_breakdown": metrics["status_counts"],
        "latency_percentiles_ms": metrics["latency_stats"],
        "error_diagnostics": metrics["error_counts"],
    }

    if metrics.get("assertions_configured"):
        data["metadata"]["assertions_compliance_rate_percent"] = metrics["assertions_compliance_rate"]
        data["metadata"]["assertions_passed_count"] = metrics["assertions_passed_count"]
        data["metadata"]["assertions_failed_count"] = metrics["assertions_failed_count"]
        data["metadata"]["sla_breached_count"] = metrics["sla_breached_count"]

    if not summary_only:
        data["results"] = []
        for r in all_results:
            item = {
                "url_id": r.url_id,
                "url": r.url,
                "status_code": r.status,
                "status_label": r.status_label,
                "attempts": getattr(r, "attempts", 1),
                "elapsed_ms": round(r.elapsed * 1000.0, 3),
                "ip_port": r.ip_port,
                "redirect_to": r.redirect_to,
                "redirect_ip_port": r.redirect_ip_port,
                "error_category": getattr(r, "error_category", None),
            }
            if r.assertions_passed is not None:
                item["assertions_passed"] = r.assertions_passed
                item["assertion_failures"] = r.assertion_failures
            if r.sla_breached or r.assertions_passed is not None:
                item["sla_breached"] = r.sla_breached
            data["results"].append(item)

    return json.dumps(data, indent=2)


def generate_csv_report(
    status_codes: dict[str, list[UrlResult]],
    summary_only: bool = False,
) -> str:
    """Generate RFC 4180 compliant CSV report string."""
    all_results = [r for sublist in status_codes.values() for r in sublist]
    all_results.sort(key=lambda r: getattr(r, "url_id", 0))

    metrics = extract_scan_metrics(all_results)
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")

    if summary_only:
        writer.writerow(["metric", "value"])
        writer.writerow(["total_scanned", metrics["total_scanned"]])
        writer.writerow(["available_count", metrics["available_count"]])
        writer.writerow(["failed_count", metrics["failed_count"]])
        writer.writerow(["availability_rate_percent", f"{metrics['availability_rate']}%"])
        for group, count in metrics["status_counts"].items():
            writer.writerow([f"status_{group}", count])
        for metric, val in metrics["latency_stats"].items():
            writer.writerow([f"latency_{metric}_ms", val])
        for err, count in metrics["error_counts"].items():
            writer.writerow([f"error_{err}", count])
        if metrics.get("assertions_configured"):
            writer.writerow(["assertions_compliance_rate_percent", f"{metrics['assertions_compliance_rate']}%"])
            writer.writerow(["assertions_passed_count", metrics["assertions_passed_count"]])
            writer.writerow(["assertions_failed_count", metrics["assertions_failed_count"]])
            writer.writerow(["sla_breached_count", metrics["sla_breached_count"]])
    else:
        headers = [
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
        if metrics.get("assertions_configured"):
            headers.extend(["assertions_passed", "assertion_failures", "sla_breached"])
        writer.writerow(headers)

        for r in all_results:
            row = [
                r.url_id,
                r.url,
                r.status if r.status is not None else "",
                r.status_label,
                getattr(r, "attempts", 1),
                f"{r.elapsed * 1000.0:.3f}",
                r.ip_port,
                r.redirect_to or "",
                r.redirect_ip_port or "",
                getattr(r, "error_category", "") or "",
            ]
            if metrics.get("assertions_configured"):
                row.extend([
                    "" if r.assertions_passed is None else ("true" if r.assertions_passed else "false"),
                    "; ".join(r.assertion_failures) if r.assertion_failures else "",
                    "true" if r.sla_breached else "false",
                ])
            writer.writerow(row)

    return out.getvalue()


def generate_markdown_report(
    status_codes: dict[str, list[UrlResult]],
    summary_only: bool = False,
) -> str:
    """Generate GitHub Flavored Markdown report string."""
    all_results = [r for sublist in status_codes.values() for r in sublist]
    all_results.sort(key=lambda r: getattr(r, "url_id", 0))

    metrics = extract_scan_metrics(all_results)
    lines = [
        "# 🐼 PingPanda Scan Report",
        "",
        "## Summary",
        f"- **Total Scanned:** {metrics['total_scanned']} URLs",
        f"- **Availability Rate:** {metrics['availability_rate']}%",
        "- **Status Breakdown:** "
        + " | ".join(f"{k}: {v}" for k, v in metrics["status_counts"].items()),
    ]

    if metrics.get("assertions_configured"):
        lines.append(
            f"- **Assertion Compliance:** {metrics['assertions_compliance_rate']}% "
            f"({metrics['assertions_passed_count']}/{metrics['assertions_evaluated_count']} passed)"
        )
        if metrics.get("sla_breached_count", 0) > 0:
            lines.append(f"- **SLA Breaches:** {metrics['sla_breached_count']}")

    lines.extend([
        "",
        "## Latency Distribution",
        "| Metric | Latency (ms) |",
        "| :--- | :--- |",
    ])

    lat = metrics["latency_stats"]
    lines.append(f"| **Min** | {lat['min']:.2f} ms |")
    lines.append(f"| **Mean** | {lat['mean']:.2f} ms |")
    lines.append(f"| **p50 (Median)** | {lat['p50']:.2f} ms |")
    lines.append(f"| **p95** | {lat['p95']:.2f} ms |")
    lines.append(f"| **p99** | {lat['p99']:.2f} ms |")
    lines.append(f"| **Max** | {lat['max']:.2f} ms |")

    if metrics["error_counts"]:
        lines.extend([
            "",
            "## Failure Diagnostics",
            "| Error Category | Count |",
            "| :--- | :--- |",
        ])
        for err, count in sorted(metrics["error_counts"].items()):
            lines.append(f"| `{err}` | {count} |")

    if not summary_only and all_results:
        if metrics.get("assertions_configured"):
            lines.extend([
                "",
                "## Detailed Results",
                "| ID | URL | Status | Attempts | Latency | IP:Port | Assertions | SLA | Error Category |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for r in all_results:
                status = str(r.status) if r.status is not None else r.status_label
                attempts = getattr(r, "attempts", 1)
                err_cat = f"`{r.error_category}`" if getattr(r, "error_category", None) else "-"
                assert_status = (
                    "PASSED"
                    if r.assertions_passed is True
                    else (
                        f"FAILED ({'; '.join(r.assertion_failures)})"
                        if r.assertions_passed is False
                        else "-"
                    )
                )
                sla_status = "BREACHED" if r.sla_breached else "Met"
                lines.append(
                    f"| {r.url_id} | {r.url} | {status} | {attempts} | {r.elapsed * 1000.0:.2f} ms | {r.ip_port} | {assert_status} | {sla_status} | {err_cat} |"
                )
        else:
            lines.extend([
                "",
                "## Detailed Results",
                "| ID | URL | Status | Attempts | Latency | IP:Port | Redirect | Error Category |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for r in all_results:
                status = str(r.status) if r.status is not None else r.status_label
                attempts = getattr(r, "attempts", 1)
                redirect = f"`{r.redirect_to}`" if r.redirect_to else "-"
                err_cat = f"`{r.error_category}`" if getattr(r, "error_category", None) else "-"
                lines.append(
                    f"| {r.url_id} | {r.url} | {status} | {attempts} | {r.elapsed * 1000.0:.2f} ms | {r.ip_port} | {redirect} | {err_cat} |"
                )

    lines.append("")
    return "\n".join(lines)


def generate_text_report(
    status_codes: dict[str, list[UrlResult]],
    summary_only: bool = False,
) -> str:
    """Generate plaintext report string."""
    lines = []
    if not summary_only:
        for group, results in status_codes.items():
            if not results:
                continue
            lines.append(f"===== {group.upper()} =====")
            for result in results:
                lines.append(format_result_line(result))
    lines.append("===== SUMMARY =====")
    lines.append(summarize(status_codes))
    metrics = extract_scan_metrics(status_codes)
    if metrics.get("assertions_configured"):
        lines.append(
            f"[Assertions] {metrics['assertions_passed_count']}/{metrics['assertions_evaluated_count']} "
            f"Passed ({metrics['assertions_compliance_rate']}%)"
        )
        if metrics.get("sla_breached_count", 0) > 0:
            lines.append(f"[SLA Checks] {metrics['sla_breached_count']} endpoint(s) breached latency threshold")
    lines.append("")
    return "\n".join(lines)


# Print the report to the terminal
def render_report(
    status_codes: dict[str, list[UrlResult]],
    no_colour: bool = False,
    summary_only: bool = False,
) -> None:
    if not summary_only:
        for group, results in status_codes.items():
            if not results:
                continue

            heading = f"===== {group.upper()} ====="

            if no_colour:
                print(heading)
            else:
                print(COLORS.get(group, Fore.WHITE) + heading)

            for result in results:
                print(format_result_line(result))
                print()

            if not no_colour:
                print(Style.RESET_ALL)

    print("===== SUMMARY =====")
    print(summarize(status_codes))

    metrics = extract_scan_metrics(status_codes)
    if metrics.get("assertions_configured"):
        compliance_str = (
            f"[Assertions] {metrics['assertions_passed_count']}/{metrics['assertions_evaluated_count']} "
            f"Passed ({metrics['assertions_compliance_rate']}%)"
        )
        if not no_colour:
            color = Fore.GREEN if metrics["assertions_failed_count"] == 0 else Fore.RED
            print(color + compliance_str + Style.RESET_ALL)
        else:
            print(compliance_str)

        if metrics.get("sla_breached_count", 0) > 0:
            sla_str = f"[SLA Checks] {metrics['sla_breached_count']} endpoint(s) breached latency threshold"
            if not no_colour:
                print(Fore.YELLOW + sla_str + Style.RESET_ALL)
            else:
                print(sla_str)


# Write the report to a file
def save_report(
    status_codes: dict[str, list[UrlResult]],
    path: str,
    format: str = "text",
    summary_only: bool = False,
) -> None:
    normalized_format = (format or "text").lower()

    if normalized_format == "json":
        content = generate_json_report(status_codes, summary_only=summary_only)
    elif normalized_format == "csv":
        content = generate_csv_report(status_codes, summary_only=summary_only)
    elif normalized_format in ("markdown", "md"):
        content = generate_markdown_report(status_codes, summary_only=summary_only)
    elif normalized_format == "text":
        content = generate_text_report(status_codes, summary_only=summary_only)
    else:
        raise ValueError(f"Unsupported report format: {format}")

    with open(path, "w", encoding="utf-8") as file:
        file.write(content)

    print(f"[Report] Saved {normalized_format.upper()} report to {path}")
