"""Tests for the terminal report and the report file."""

import re

import pytest

KNOWN_DEFECT = "known defect - see the FOSSSoC-S1 issue tracker"


def test_result_line_contains_the_important_details(checker, make_result):
    line = checker.format_result_line(make_result(status=200, url="https://example.com"))

    assert "[Status: 200]" in line
    assert "https://example.com" in line
    assert "[IP:" in line
    assert "[Redirect: None]" in line
    assert "[Time:" in line


def test_result_line_contains_the_redirect_details(checker, make_result):
    result = make_result(
        status=200,
        redirect_to="https://target.test/final",
        redirect_ip_port="10.0.0.2:443",
    )
    line = checker.format_result_line(result)

    assert "[Redirect: https://target.test/final (10.0.0.2:443)]" in line


def test_invalid_url_is_labelled_as_invalid(checker, make_result):
    line = checker.format_result_line(make_result(status=None))
    assert "[Status: Invalid]" in line


def test_report_contains_every_status_group(checker, make_result, capsys):
    results = {
        0: make_result(status=200, url="https://good.test/"),
        1: make_result(status=404, url="https://missing.test/"),
        2: make_result(status=None, url="https://down.test/"),
    }
    groups = checker.classify_results(results)
    checker.render_report(groups)

    out = capsys.readouterr().out
    assert "===== 2XX =====" in out
    assert "===== 4XX =====" in out
    assert "===== INVALID =====" in out
    assert "===== SUMMARY =====" in out
    assert "https://good.test/" in out
    assert "https://missing.test/" in out
    assert "https://down.test/" in out


def test_summary_counts_every_checked_url(checker, make_result):
    results = {
        0: make_result(status=200),
        1: make_result(status=404),
        2: make_result(status=None),
    }
    summary = checker.summarize(checker.classify_results(results))

    assert "Checked: 3" in summary


def test_summary_counts_the_failed_urls(checker, make_result):
    results = {
        0: make_result(status=200),
        1: make_result(status=None),
        2: make_result(status=None),
    }
    summary = checker.summarize(checker.classify_results(results))

    assert "Failed: 2" in summary


def test_report_file_keeps_every_status_group(checker, make_result, tmp_path):
    results = {
        0: make_result(status=200, url="https://good.test/"),
        1: make_result(status=404, url="https://missing.test/"),
    }
    groups = checker.classify_results(results)
    report = tmp_path / "report.txt"
    checker.save_report(groups, str(report))

    content = report.read_text(encoding="utf-8")
    assert "===== 2XX =====" in content
    assert "===== 4XX =====" in content
    assert "https://good.test/" in content
    assert "https://missing.test/" in content
