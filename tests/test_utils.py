import pytest
from nextsec import utils

def test_sanitize():
    assert utils.sanitize("good") == "good"
    assert utils.sanitize("with-dash") == "with_dash"
