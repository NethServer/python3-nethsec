# python3-nextsec

Python3 library for Nextsecurity

Requirements:

* Python3
* [pyuci](https://gitlab.nic.cz/turris/pyuci)

## Usage

The `nextsec` library is composed by the following sub-packages:

- utils
- firewall

Usage example:
```python
from euci import EUci
from nextsec import firewall

u = EUci()
firewall.add_to_lan(u, 'tunrw')
firewall.allow_service(u, 'openvpn_rw', '1194', 'udp')
firewall.apply(u)
```

## Documentation

Execute:
```bash
python3 -m pydoc nextsec.firewall
python3 -m pydoc nextsec.utilities
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
