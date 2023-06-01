# python3-nethsec

Python3 library for NethSecurity

Requirements:

* Python3
* [pyuci](https://gitlab.nic.cz/turris/pyuci)

[![Run tests](https://github.com/NethServer/python3-nethsec/actions/workflows/run-tests.yaml/badge.svg?branch=master)](https://github.com/NethServer/python3-nethsec/actions/workflows/run-tests.yaml)

## Usage

The `nethsec` library is composed by the following sub-packages:

- utils
- firewall

Usage example:
```python
from euci import EUci
from nethsec import firewall

u = EUci()
firewall.add_to_lan(u, 'tunrw')
firewall.add_service(u, 'openvpn_rw', '1194', ['udp', 'tcp'])
firewall.apply(u)
```

## Documentation

Execute:
```bash
python3 -m pydoc nethsec.firewall
python3 -m pydoc nethsec.utils
```

## Build

Execute:
```bash
python3 -m pip install --upgrade build
python3 -m pip install wheel
python3 -m build
```

## Tests

Tests run inside a podman container based on Ubuntu with Python 3.10.

To start the tests, first make sure to have podman installed. Then, from the repository root directory execute:
```
./test.sh
```
