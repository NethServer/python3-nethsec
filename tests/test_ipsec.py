import pathlib

import pytest
from euci import EUci
from pytest_mock import MockFixture
from nethsec import ipsec
from nethsec.utils import ValidationError

ipsec_db = """
"""

@pytest.fixture
def e_uci(tmp_path: pathlib.Path) -> EUci:
    conf_dir = tmp_path.joinpath('conf')
    conf_dir.mkdir()
    save_dir = tmp_path.joinpath('save')
    save_dir.mkdir()
    return EUci(confdir=conf_dir.as_posix(), savedir=save_dir.as_posix())


@pytest.fixture
def e_uci_with_data(e_uci: EUci):
    with pathlib.Path(e_uci.confdir()).joinpath('dpi').open('w') as fp:
        fp.write(dpi_db)
    return e_uci


def test_init_ipsec(e_uci):
    ipsec.init_ipsec(e_uci)
    assert(e_uci.get('ipsec', 'ns_ipsec_global') == 'ipsec')
    assert(e_uci.get('ipsec', 'ns_ipsec_global', 'debug') == '0')
    assert(e_uci.get('ipsec', 'ns_ipsec_global', 'zone') == ipsec.IPSEC_ZONE)
    assert(e_uci.get_all('ipsec', 'ns_ipsec_global', 'interface') == ('wan',))
