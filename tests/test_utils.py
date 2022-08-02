import pytest
from nextsec import utils

def test_sanitize():
    assert utils.sanitize("good") == "good"
    assert utils.sanitize("with-dash") == "with_dash"
    assert utils.sanitize('$%_()') == '_____'
    assert utils.sanitize('UPPER') == 'UPPER'
    assert utils.sanitize('numb3r') == 'numb3r'
    assert utils.sanitize('newline\n') == 'newline_'
    assert utils.sanitize('newline\r') == 'newline_'

def test_get_id():
    assert utils.get_id('no-good') == 'ns_no_good'
    assert utils.get_id('nospace ') == 'ns_nospace_'
    assert utils.get_id('111111111111111') == 'ns_111111111111'
    assert utils.get_id('111111111111') == 'ns_111111111111'

