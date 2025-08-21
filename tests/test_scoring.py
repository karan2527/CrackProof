import pytest

from CrackProof.crackproof import (
    score_password,
    has_sequential_runs,
    has_repeated_patterns,
    has_keyboard_runs,
    dictionary_match,
)


def test_score_increases_with_length():
    short = score_password("Ab1!", check_breach=False)["score"]
    longer = score_password("Ab1!Ab1!Ab1!", check_breach=False)["score"]
    assert longer >= short


@pytest.mark.parametrize("pw", ["abcd", "4321", "qwer", "0987"])
def test_sequential_runs_detected(pw):
    assert has_sequential_runs(pw)


@pytest.mark.parametrize("pw", ["abab", "123123", "aaaa"])
def test_repeated_patterns_detected(pw):
    assert has_repeated_patterns(pw)


@pytest.mark.parametrize("pw", ["qwerty", "!@#$%", "poiuy"])
def test_keyboard_runs_detected(pw):
    assert has_keyboard_runs(pw)


@pytest.mark.parametrize("pw", ["password1", "P@ssw0rd", "LetMeIn123"]) 
def test_dictionary_match_detected(pw):
    assert dictionary_match(pw)


