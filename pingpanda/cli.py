"""Command-line interface for PingPanda."""

from __future__ import annotations

import argparse
import math
import sys

from pingpanda.checkpoint import CheckpointError, load_checkpoint, save_checkpoint
from pingpanda.constants import BANNER
from pingpanda.assertions import (
    AssertionConfig,
    parse_expect_header_option,
    parse_header_option,
    parse_status_codes,
)
from pingpanda.network import (
    check_all,
    DEFAULT_MAX_CONCURRENT,
    DEFAULT_RETRIES,
    DEFAULT_RETRY_DELAY_SECONDS,
)
from pingpanda.report import classify_results, render_report, save_report

DEFAULT_CHECKPOINT = ".pingpanda-checkpoint.json"


def make_output_safe():
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError):
            pass


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")

    return number


def non_negative_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if number < 0:
        raise argparse.ArgumentTypeError("must not be negative")

    return number


def non_negative_float(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number")

    if number < 0 or not math.isfinite(number):
        raise argparse.ArgumentTypeError("must be a finite, non-negative number")

    return number


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description="URL Status Checker")
    parser.add_argument("-d", "--domain", help="Single domain/URL to check")
    parser.add_argument("-l", "--list", help="File containing list of domains/URLs to check")
    parser.add_argument("-o", "--output", help="File to save the output")

    parser.add_argument(
        "--checkpoint",
        default=DEFAULT_CHECKPOINT,
        metavar="PATH",
        help=f"Checkpoint file (default: {DEFAULT_CHECKPOINT})",
    )
    parser.add_argument(
        "--retries",
        type=non_negative_int,
        default=DEFAULT_RETRIES,
        help="Retries after transient failures (default: 0)",
    )
    parser.add_argument(
        "--retry-delay",
        type=non_negative_float,
        default=DEFAULT_RETRY_DELAY_SECONDS,
        help="Initial retry delay in seconds; delays double after each retry",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume unfinished URLs from the checkpoint file",
    )
    parser.add_argument("-v", "--version", action="store_true", help="Display version information")
    parser.add_argument("-update", action="store_true", help="Update the tool")

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the startup banner and progress bar",
    )
    parser.add_argument(
        "--no-colour",
        action="store_true",
        help="Disable coloured terminal output",
    )
    parser.add_argument(
        "--max-concurrent",
        type=positive_int,
        default=DEFAULT_MAX_CONCURRENT,
        help="Maximum number of URLs to check concurrently (default: 10)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv", "markdown"],
        default="text",
        help="Export format for the report (default: text)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Export summary statistics and latency percentiles only",
    )

    parser.add_argument(
        "-H",
        "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="Custom request header to send with checks (e.g. 'Authorization: Bearer token'). Repeatable.",
    )
    parser.add_argument(
        "--expect-status",
        metavar="CODES",
        help="Expected HTTP status code(s) or ranges, comma-separated (e.g. '200,204' or '200-299')",
    )
    parser.add_argument(
        "--expect-body",
        metavar="TEXT",
        help="Expected substring in response body",
    )
    parser.add_argument(
        "--expect-body-regex",
        metavar="REGEX",
        help="Expected regular expression pattern matching response body",
    )
    parser.add_argument(
        "--expect-header",
        action="append",
        dest="expect_headers",
        metavar="HEADER",
        help="Expected response header to validate (e.g. 'Content-Type: application/json' or 'Content-Type'). Repeatable.",
    )
    parser.add_argument(
        "--max-latency",
        type=non_negative_float,
        default=None,
        metavar="SECONDS",
        help="Maximum acceptable response time SLA in seconds (e.g. 0.5 for 500ms)",
    )

    return parser.parse_args(argv)


def build_assertion_config(args: argparse.Namespace) -> AssertionConfig | None:
    """Build an AssertionConfig from parsed CLI arguments, or None if no assertions configured."""
    import re

    custom_headers: dict[str, str] = {}
    if getattr(args, "headers", None):
        for h in args.headers:
            name, val = parse_header_option(h)
            custom_headers[name] = val

    expect_status: set[int] | None = None
    if getattr(args, "expect_status", None):
        expect_status = parse_status_codes(args.expect_status)

    expect_body = getattr(args, "expect_body", None)

    expect_body_regex = None
    if getattr(args, "expect_body_regex", None):
        try:
            expect_body_regex = re.compile(args.expect_body_regex)
        except re.error as exc:
            raise ValueError(f"Invalid regex for --expect-body-regex: {exc}") from exc

    expect_headers: dict[str, str | None] = {}
    if getattr(args, "expect_headers", None):
        for eh in args.expect_headers:
            name, val = parse_expect_header_option(eh)
            expect_headers[name] = val

    max_latency = getattr(args, "max_latency", None)

    if (
        not custom_headers
        and expect_status is None
        and expect_body is None
        and expect_body_regex is None
        and not expect_headers
        and max_latency is None
    ):
        return None

    return AssertionConfig(
        expect_status=expect_status,
        expect_body=expect_body,
        expect_body_regex=expect_body_regex,
        expect_headers=expect_headers,
        max_latency=max_latency,
        custom_headers=custom_headers,
    )


def load_urls(args):
    if args.domain:
        url = args.domain.strip()
        return [url] if url else []

    if args.list:
        with open(args.list, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]

    return None


async def main(argv=None):
    make_output_safe()
    args = parse_arguments(argv)

    if args.version:
        print("StatusChecker.py version 1.0")
        return

    if args.update:
        print("Checking for updates...")
        return

    if not args.quiet:
        print(BANNER)

    urls = load_urls(args)
    if not urls:
        print("No input provided. Use -d or -l option.")
        return

    initial_results = {}

    if args.resume:
        try:
            initial_results = load_checkpoint(args.checkpoint, urls)
        except CheckpointError as exc:
            print(f"Checkpoint error: {exc}", file=sys.stderr)
            return

        print(
            f"Resuming scan: {len(initial_results)} "
            f"of {len(urls)} URLs already completed."
        )

    try:
        assertion_config = build_assertion_config(args)
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return

    def persist_progress(completed_results):
        save_checkpoint(args.checkpoint, urls, completed_results)

    try:
        results = await check_all(
            urls,
            initial_results=initial_results,
            on_result=persist_progress,
            max_concurrent=args.max_concurrent,
            show_progress=not args.quiet,
            max_retries=args.retries,
            retry_delay=args.retry_delay,
            assertion_config=assertion_config,
        )

        # Also create a checkpoint for an empty or already-complete resumed scan.
        save_checkpoint(args.checkpoint, urls, results)

    except CheckpointError as exc:
        print(f"Checkpoint error: {exc}", file=sys.stderr)
        return

    status_codes = classify_results(results)

    render_report(
        status_codes,
        no_colour=args.no_colour,
        summary_only=args.summary_only,
    )

    if args.output:
        save_report(
            status_codes,
            args.output,
            format=args.format,
            summary_only=args.summary_only,
        )
