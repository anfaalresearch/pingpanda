"""The arguments of the tool and what it does with them."""

from __future__ import annotations

import argparse
import sys

from pingpanda.constants import BANNER
from pingpanda.network import check_all
from pingpanda.report import classify_results, render_report, save_report


# Make sure the terminal is able to print the banner
def make_output_safe():
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError):
            pass


# Argument parser
def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description="URL Status Checker")
    parser.add_argument("-d", "--domain", help="Single domain/URL to check")
    parser.add_argument("-l", "--list", help="File containing list of domains/URLs to check")
    parser.add_argument("-o", "--output", help="File to save the output")
    parser.add_argument("-v", "--version", action="store_true", help="Display version information")
    parser.add_argument("-update", action="store_true", help="Update the tool")
    return parser.parse_args(argv)


# Read the URLs the user asked for
def load_urls(args):
    urls = set()

    if args.domain:
        urls.add(args.domain)
    elif args.list:
        with open(args.list, "r") as file:
            urls.update(file.read().splitlines())
    else:
        return None

    return urls


# Main function
async def main(argv=None):
    make_output_safe()
    args = parse_arguments(argv)

    if args.version:
        print("StatusChecker.py version 1.0")
        return

    if args.update:
        print("Checking for updates...")  # Implement update logic here
        return

    print(BANNER)

    try:
        urls = load_urls(args)
    except FileNotFoundError:
        print(f"Error: file not found: {args.list}")
        return

    if not urls:
        print("No input provided. Use -d or -l option.")
        return

    results = await check_all(urls)
    status_codes = classify_results(results)
    render_report(status_codes)

    if args.output:
        save_report(status_codes, args.output)
