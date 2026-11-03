"""Tests for the way results are grouped by HTTP status class."""

import pytest

KNOWN_DEFECT = "known defect - see the FOSSSoC-S1 issue tracker"


def test_success_is_grouped_as_2xx(checker, make_result):
    groups = checker.classify_results({0: make_result(status=200)})
    assert len(groups["2xx"]) == 1


def test_redirect_is_grouped_as_3xx(checker, make_result):
    groups = checker.classify_results({0: make_result(status=302)})
    assert len(groups["3xx"]) == 1


def test_client_error_is_grouped_as_4xx(checker, make_result):
    groups = checker.classify_results({0: make_result(status=404)})
    assert len(groups["4xx"]) == 1


def test_server_error_is_grouped_as_5xx(checker, make_result):
    groups = checker.classify_results({0: make_result(status=500)})
    assert len(groups["5xx"]) == 1


def test_unreachable_url_is_grouped_as_invalid(checker, make_result):
    groups = checker.classify_results({0: make_result(status=None)})
    assert len(groups["Invalid"]) == 1


def test_every_result_ends_up_in_exactly_one_group(checker, make_result):
    results = {
        0: make_result(status=200),
        1: make_result(status=404),
        2: make_result(status=500),
        3: make_result(status=None),
    }
    groups = checker.classify_results(results)

    assert sum(len(group) for group in groups.values()) == len(results)
