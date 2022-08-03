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
    assert utils.get_id('t1234') == 'ns_t1234'
    # str with 97 chars
    long_str = "ihTSEf2Y5rl8TX96pWFFPMty9LFgH3GezhVueGoDB6_aaIFhDSKe1ZR64cV41iSVhfrm5wJCUPFfMGx2fBZyhDIW9cl9SCI43"
    assert utils.get_id(long_str) == f'ns_{long_str}'
    assert utils.get_id(long_str+"123") == f'ns_{long_str}'

