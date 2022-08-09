import pytest
from nextsec import utils
from euci import EUci

test_db = """
config mytype section1
	option name 'myname1'

config mytype section2
	option name 'myname2'
	list opt1 'val1'
	list opt1 'val2'

config mytype2 section3
	option name 'myname3'
"""

def _setup_db(tmp_path):
     # setup fake db
    with tmp_path.joinpath('test').open('w') as fp:
        fp.write(test_db)
    return EUci(confdir=tmp_path.as_posix())

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

def test_get_id_lenght():
    assert utils.get_id("123456789012345", 15) == "ns_123456789012"

def test_get_all_by_type(tmp_path):
    u = _setup_db(tmp_path)
    records = utils.get_all_by_type(u, 'test', 'mytype')
    assert records != None
    assert 'section1' in records.keys()
    assert 'section2' in records.keys()
    assert 'section3' not in records.keys()
    assert records['section1']['name'] == 'myname1'
    assert records['section2']['name'] == 'myname2'
    assert records['section2']['opt1'] == ('val1', 'val2')
