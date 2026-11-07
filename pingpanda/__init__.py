"""
PingPanda - a friendly command line website health checker.

PingPanda started its life as "Status Checker", written by BLACK-SCORP10
(https://github.com/BLACK-SCORP10/url-status-checker) and later enhanced by
matteocapricci.  The original project, its ideas and its output format are
kept intact here; the tool is maintained during the FOSSSoC-S1 season.

The package is split into small modules, every module has one job:

* ``pingpanda.constants`` - the texts and the colours that are printed
* ``pingpanda.models``    - the data that is kept about a checked URL
* ``pingpanda.network``   - resolving a host and checking a URL
* ``pingpanda.report``    - turning the results into the report
* ``pingpanda.cli``       - the arguments and what the tool does with them

Released under the MIT License - see the LICENSE file.
"""

from pingpanda.cli import load_urls, main, parse_arguments
from pingpanda.constants import BANNER, COLORS, STATUS_GROUPS
from pingpanda.models import UrlResult
from pingpanda.network import (
    check_all,
    check_url_status,
    normalize_url,
    resolve_ip_and_port,
)
from pingpanda.report import (
    classify_results,
    compute_latency_percentiles,
    extract_scan_metrics,
    format_result_line,
    generate_csv_report,
    generate_json_report,
    generate_markdown_report,
    generate_text_report,
    render_report,
    save_report,
    summarize,
)

__all__ = [
    "BANNER",
    "COLORS",
    "STATUS_GROUPS",
    "UrlResult",
    "check_all",
    "check_url_status",
    "classify_results",
    "compute_latency_percentiles",
    "extract_scan_metrics",
    "format_result_line",
    "generate_csv_report",
    "generate_json_report",
    "generate_markdown_report",
    "generate_text_report",
    "load_urls",
    "main",
    "normalize_url",
    "parse_arguments",
    "render_report",
    "resolve_ip_and_port",
    "save_report",
    "summarize",
]
