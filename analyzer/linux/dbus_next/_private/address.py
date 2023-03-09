from ..constants import BusType
from ..errors import InvalidAddressError

from urllib.parse import unquote
import re
import os

invalid_address_chars_re = re.compile(r'[^-0-9A-Za-z_/.%]')


def parse_address(address_str):
    addresses = []

    for address in filter(lambda a: a, address_str.split(';')):
        if address.find(':') == -1:
            raise InvalidAddressError('address did not contain a transport')

        transport, opt_string = address.split(':', 1)
        options = {}

        for kv in filter(lambda s: s, opt_string.split(',')):
            if kv.find('=') == -1:
                raise InvalidAddressError('address option did not contain a value')
            k, v = kv.split('=', 1)
            if invalid_address_chars_re.search(v):
                raise InvalidAddressError('address contains invalid characters')
            # XXX the actual unquote rules are simpler than this
            v = unquote(v)
            options[k] = v

        addresses.append((transport, options))

    if not addresses:
        raise InvalidAddressError(f'address string contained no addresses: "{address_str}"')

    return addresses


def get_system_bus_address():
    if 'DBUS_SYSTEM_BUS_ADDRESS' in os.environ:
        return os.environ['DBUS_SYSTEM_BUS_ADDRESS']
    else:
        return 'unix:path=/var/run/dbus/system_bus_socket'


display_re = re.compile(r'.*:([0-9]+)\.?.*')
remove_quotes_re = re.compile(r'''^['"]?(.*?)['"]?$''')


def get_session_bus_address():
    if 'DBUS_SESSION_BUS_ADDRESS' in os.environ:
        return os.environ['DBUS_SESSION_BUS_ADDRESS']

    home = os.environ['HOME']
    if 'DISPLAY' not in os.environ:
        raise InvalidAddressError(
            'DBUS_SESSION_BUS_ADDRESS not set and could not get DISPLAY environment variable to get bus address'
        )

    display = os.environ['DISPLAY']
    try:
        display = display_re.search(display).group(1)
    except Exception:
        raise InvalidAddressError(
            f'DBUS_SESSION_BUS_ADDRESS not set and could not parse DISPLAY environment variable to get bus address: {display}'
        )

    # XXX: this will block but they're very small files and fs operations
    # should be fairly reliable. fix this by passing in an async func to read
    # the file for each io backend.
    machine_id = None
    with open('/var/lib/dbus/machine-id') as f:
        machine_id = f.read().rstrip()

    dbus_info_file_name = f'{home}/.dbus/session-bus/{machine_id}-{display}'
    dbus_info = None
    try:
        with open(dbus_info_file_name) as f:
            dbus_info = f.read().rstrip()
    except Exception:
        raise InvalidAddressError(f'could not open dbus info file: {dbus_info_file_name}')

    for line in dbus_info.split('\n'):
        if line.strip().startswith('DBUS_SESSION_BUS_ADDRESS='):
            _, addr = line.split('=', 1)
            if not addr:
                raise InvalidAddressError(
                    f'DBUS_SESSION_BUS_ADDRESS variable not set correctly in dbus info file: {dbus_info_file_name}'
                )
            addr = remove_quotes_re.search(addr).group(1)
            return addr

    raise InvalidAddressError('could not find dbus session bus address')


def get_bus_address(bus_type):
    if bus_type == BusType.SESSION:
        return get_session_bus_address()
    elif bus_type == BusType.SYSTEM:
        return get_system_bus_address()
    else:
        raise Exception('got unknown bus type: {bus_type}')
