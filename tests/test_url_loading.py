"""Tests for reading the URLs the user asked for."""

import asyncio

import pytest

KNOWN_DEFECT = "known defect - see the FOSSSoC-S1 issue tracker"


def test_domain_option_is_used(checker):
    args = checker.parse_arguments(["-d", "https://example.com"])
    assert checker.load_urls(args) == {"https://example.com"}


def test_list_option_is_used(checker, tmp_path):
    list_file = tmp_path / "urls.txt"
    list_file.write_text("https://a.test\nhttps://b.test\n", encoding="utf-8")

    args = checker.parse_arguments(["-l", str(list_file)])
    assert checker.load_urls(args) == {"https://a.test", "https://b.test"}


def test_without_input_no_url_is_loaded(checker):
    args = checker.parse_arguments([])
    assert checker.load_urls(args) is None


def test_missing_list_file_does_not_crash_the_tool(checker, tmp_path):
    missing = tmp_path / "there-is-no-such-file.txt"

    try:
        asyncio.run(checker.main(["-l", str(missing)]))
    except FileNotFoundError:
        pytest.fail("the tool died with a raw FileNotFoundError")
