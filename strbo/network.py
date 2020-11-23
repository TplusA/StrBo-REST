#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2018, 2019, 2020  T+A elektroakustik GmbH & Co. KG
#
# This file is part of StrBo-REST.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.


from threading import RLock
from werkzeug.wrappers import Response
from werkzeug.exceptions import NotFound
from json import loads
import halogen

from .endpoint import Endpoint, register_endpoints
from .utils import jsonify_e, jsonify_simple, jsonify_error, if_none_match
from .utils import get_logger
import strbo.dbus
import dbus.exceptions
log = get_logger()


def _assert_list_of_strings_or_empty(ls):
    if ls is None:
        return

    assert isinstance(ls, list)

    for elem in ls:
        assert isinstance(elem, str)
        assert elem


class _IPConfiguration:
    """Generic set of IP configuration settings, any version."""
    def __init__(self, dhcp_method, address, gateway):
        self.dhcp_method = dhcp_method
        self.address = address
        self.gateway = gateway


class _IPv4Configuration(_IPConfiguration):
    """Set of IPv4 configuration settings."""

    def __init__(self, dhcp_method, address, netmask, gateway):
        super().__init__(dhcp_method, address, gateway)
        self.netmask = netmask

    @staticmethod
    def from_json(config):
        if not config:
            return _IPv4Configuration('auto', None, None, None)

        method = config['dhcp_method']

        if method in ('off', 'dhcp', 'auto'):
            return _IPv4Configuration(method, None, None, None)

        if method == 'manual':
            return _IPv4Configuration(method, config['address'],
                                      config['netmask'], config['gateway'])

        raise ValueError('Invalid IPv4 DHCP method "{}"'.format(method))


class _IPv6Configuration(_IPConfiguration):
    """Set of IPv6 configuration settings."""

    def __init__(self, dhcp_method, address, prefix_length, gateway):
        super().__init__(dhcp_method, address, gateway)
        self.prefix_length = prefix_length

    @staticmethod
    def from_json(config):
        if not config:
            return _IPv6Configuration('auto', None, None, None)

        method = config['dhcp_method']

        if method in ('off', 'auto'):
            return _IPv6Configuration(method, None, None, None)

        if method == 'manual':
            return _IPv6Configuration(method, config['address'],
                                      config['prefix_length'],
                                      config['gateway'])

        raise ValueError('Invalid IPv6 DHCP method "{}"'.format(method))


class _ProxyConfiguration:
    """Set of proxy configuration settings."""

    def __init__(self, method, pac_url, servers, excludes):
        self.method = method
        self.auto_config_pac_url = pac_url
        self.proxy_servers = servers
        self.excluded_hosts = excludes

    @staticmethod
    def from_json(config):
        if not config:
            return None

        method = config['method']

        if method == 'direct':
            return _ProxyConfiguration(method, None, None, None)

        if method == 'auto':
            return _ProxyConfiguration(
                method, config.get('auto_config_pac_url', None), None, None)

        if method == 'manual':
            return _ProxyConfiguration(method, None,
                                       config.get('proxy_servers', []),
                                       config.get('excluded_hosts', []))

        raise ValueError('Invalid proxy method "{}"'.format(method))


class _ServiceConfiguration:
    """Set of common network service configuration settings."""
    def __init__(self, *, ipv4_config=None, ipv6_config=None,
                 proxy_config=None,
                 dns_servers=None, time_servers=None, domains=None):
        assert isinstance(ipv4_config, (_IPv4Configuration, type(None)))
        assert isinstance(ipv6_config, (_IPv6Configuration, type(None)))
        assert isinstance(proxy_config, (_ProxyConfiguration, type(None)))
        _assert_list_of_strings_or_empty(dns_servers)
        _assert_list_of_strings_or_empty(time_servers)
        _assert_list_of_strings_or_empty(domains)

        self.ipv4_config = ipv4_config
        self.ipv6_config = ipv6_config
        self.proxy_config = proxy_config
        self.dns_servers = dns_servers
        self.time_servers = time_servers
        self.domains = domains

    @staticmethod
    def from_json(config):
        return _ServiceConfiguration(
            ipv4_config=_IPv4Configuration.from_json(
                            config.get('ipv4_config', None)),
            ipv6_config=_IPv6Configuration.from_json(
                            config.get('ipv6_config', None)),
            proxy_config=_ProxyConfiguration.from_json(
                            config.get('proxy_config', None)),
            dns_servers=config.get('dns_servers', None),
            time_servers=config.get('time_servers', None),
            domains=config.get('domains', None))


class _ServiceConfigurationRequestWLANInfo:
    """Set of requested WLAN-specific configuration settings.

    The requested WLAN security must be specified via the ``security``
    parameter. If this parameters is set to the value ``wps``, then
    configuration over WPS is initiated.

    If sent to the :class:`Interfaces` endpoint, then the ``ssid``, the
    ``name``, or both must be filled in (where ``ssid`` takes precedence).
    If sent to the :class:`Services` endpoint, then both, ``ssid`` and
    ``name``, are ignored (in fact, these parameters do not even have to exist)
    and the SSID of the service at the endpoint is used.
    """
    def __init__(self, security, ssid=None, name=None):
        assert isinstance(security, str)
        assert isinstance(ssid, (str, type(None)))
        assert isinstance(name, (str, type(None)))

        self.security = security
        self.ssid = ssid
        self.name = name

    @staticmethod
    def from_json(info):
        result = _ServiceConfigurationRequestWLANInfo(info['security'],
                                                      info.get('ssid', None),
                                                      info.get('name', None))

        if result.ssid is not None or result.name is not None:
            return result

        raise ValueError('Network name or SSID must be provided in WLAN info')


def _object_to_dict(input_fields, obj, may_be_empty=False):
    if obj is None:
        return None

    out = {}

    for f in input_fields:
        elem = getattr(obj, f, None)
        if elem is not None:
            out[f] = elem

    if out:
        return out

    if out is None:
        return None

    return out if may_be_empty else None


def _add_to_dict(d, field, elem):
    if elem is not None:
        d[field] = elem


class _ServiceConfigurationRequest:
    """Set of requested network service configuration settings."""
    def __init__(self, supposed_config, auto_connect, *,
                 nic=None, wlan_passphrase=None, wlan_info=None):
        assert isinstance(supposed_config, _ServiceConfiguration)
        assert isinstance(auto_connect, str)
        assert isinstance(nic, (_NIC, type(None)))
        assert isinstance(wlan_passphrase, (str, type(None)))
        assert isinstance(wlan_info,
                          (_ServiceConfigurationRequestWLANInfo, type(None)))

        self.supposed_config = supposed_config
        self.auto_connect = auto_connect

        if nic is not None:
            self.nic = nic

        if wlan_passphrase is not None and wlan_info is not None:
            self.wlan_passphrase = wlan_passphrase
            self.wlan_info = wlan_info

    @staticmethod
    def from_json(settings, *, is_wlan=False, nic=None):
        cfg = _ServiceConfiguration.from_json(settings['supposed_config'])

        if not is_wlan:
            return _ServiceConfigurationRequest(cfg, settings['auto_connect'],
                                                nic=nic)

        if 'wlan_info' in settings:
            wlan_info = _ServiceConfigurationRequestWLANInfo.from_json(
                            settings['wlan_info'])
        else:
            wlan_info = None

        return _ServiceConfigurationRequest(
                        cfg, settings['auto_connect'], nic=nic,
                        wlan_passphrase=settings.get('passphrase', None),
                        wlan_info=wlan_info)

    def to_dict_for_dcpd(self):
        def ip_config_to_dict(cfg):
            fields = ('dhcp_method', 'address', 'gateway',
                      'netmask', 'prefix_length')
            return _object_to_dict(fields, cfg)

        cfg = {}
        _add_to_dict(cfg, 'ipv4_config',
                     ip_config_to_dict(self.supposed_config.ipv4_config))
        _add_to_dict(cfg, 'ipv6_config',
                     ip_config_to_dict(self.supposed_config.ipv6_config))
        _add_to_dict(cfg, 'proxy_config',
                     _object_to_dict(
                         ('method', 'auto_config_pac_url', 'proxy_servers',
                          'excluded_hosts'),
                         getattr(self.supposed_config, 'proxy_config', None),
                         True))
        _add_to_dict(cfg, 'dns_servers', self.supposed_config.dns_servers)
        _add_to_dict(cfg, 'time_servers', self.supposed_config.time_servers)
        _add_to_dict(cfg, 'domains', self.supposed_config.domains)

        d = {}
        d['configuration'] = cfg
        d['auto_connect'] = self.auto_connect

        if hasattr(self, 'nic'):
            cfg = _object_to_dict(('mac',), self.nic)

            if cfg:
                d['device_info'] = cfg

        if hasattr(self, 'wlan_info'):
            cfg = _object_to_dict(('security', 'name', 'ssid'), self.wlan_info)

            if cfg and hasattr(self, 'wlan_passphrase'):
                _add_to_dict(cfg, 'passphrase', self.wlan_passphrase)

            if cfg:
                d['wlan_settings'] = cfg

        return d


class _Service:
    """Representation of a generic network service."""
    def __init__(self, service_id, is_favorite, is_auto_connect, active_config,
                 supposed_config, is_system_service, is_cached, state):
        assert isinstance(service_id, str)
        assert service_id
        assert isinstance(is_favorite, bool)
        assert isinstance(is_auto_connect, bool)
        assert isinstance(active_config, (_ServiceConfiguration, type(None)))
        assert isinstance(supposed_config, (_ServiceConfiguration, type(None)))
        assert isinstance(is_system_service, bool)
        assert isinstance(is_cached, bool)
        assert isinstance(state, str)
        assert state

        self.id = service_id
        self.active_config = active_config
        self.supposed_config = supposed_config
        self.is_system_service = is_system_service
        self.is_favorite = is_favorite
        self.is_auto_connect = is_auto_connect
        self.is_cached = is_cached
        self.state = state

    def get_tech_and_mac(self):
        tokens = self.id.split('_')
        return (tokens[0], tokens[1].upper())


class _EthernetService(_Service):
    """Representation of an Ethernet network service."""
    def __init__(self, service_id, is_favorite, is_auto_connect, active_config,
                 supposed_config, is_system_service, is_cached, state):
        super().__init__(service_id, is_favorite, is_auto_connect,
                         active_config, supposed_config, is_system_service,
                         is_cached, state)

    def get_name(self):
        return 'Wired'


class _WLANService(_Service):
    """Representation of a WLAN network service."""
    def __init__(self, service_id, is_favorite, is_auto_connect, active_config,
                 supposed_config, is_system_service, is_cached, state, *,
                 security=None, strength=-1,
                 wps_capability=False, wps_active=False):
        _assert_list_of_strings_or_empty(security)
        assert isinstance(strength, int)
        assert isinstance(wps_capability, bool)
        assert isinstance(wps_active, bool)

        super().__init__(service_id, is_favorite, is_auto_connect,
                         active_config, supposed_config, is_system_service,
                         is_cached, state)

        self.security = security
        self.strength = strength
        self.wps_capability = wps_capability
        self.wps_active = wps_active

    def get_ssid(self):
        return self.id.split('_')[2]

    def get_name(self):
        ssid = self.get_ssid()

        try:
            return ''.join([
                chr(int(ssid[i:i + 2], 16)) for i in range(0, len(ssid), 2)])
        except:  # noqa: E722
            return None


class _NIC:
    """Representation of a network interface controller (NIC).

    A NIC object also stores all network services tied to that NIC. All NIC and
    service settings are queried directly from ConnMan.
    """
    def __init__(self, devname, technology, mac, is_cached):
        assert isinstance(devname, str)
        assert devname
        assert isinstance(technology, str)
        assert technology
        assert isinstance(mac, str)
        assert mac
        assert isinstance(is_cached, bool)

        self.devname = devname
        self.technology = technology
        self.mac = mac.upper()
        self.is_cached = is_cached
        self.services = {}

    def __iter__(self):
        return iter(self.services)

    def add_service(self, service):
        assert isinstance(service, _Service)
        self.services[service.id] = service

    def remove_service(self, id):
        try:
            service = self.services[id]
            del self.services[id]
        except KeyError:
            return None

        return service

    def mark_as_secondary(self):
        self.is_secondary = True

    def get_service_by_id(self, id):
        try:
            return self.services[id]
        except KeyError:
            return None

    def get_mac_address(self):
        return ':'.join([
            self.mac[i:i + 2].upper() for i in range(0, 12, 2)])

    @staticmethod
    def parse_mac_address(mac):
        m = ''.join([mac[i:i + 2].upper() for i in range(0, 16, 3)])

        count = sum(1 if c in ('0', '1', '2', '3', '4', '5', '6', '7', '8',
                               '9', 'A', 'B', 'C', 'D', 'E', 'F') else 0
                    for c in m)

        if count != 2 * 6:
            raise ValueError('Invalid MAC address "{}"'.format(mac))

        return m.upper()


class _EthernetNIC(_NIC):
    """Representation of an Ethernet network interface controller."""
    def __init__(self, devname, mac, is_cached):
        super().__init__(devname, 'ethernet', mac, is_cached)

    def add_service(self, service):
        assert isinstance(service, _EthernetService)
        super().add_service(service)

    def get_max_age(self):
        return 8 * 3600


class _WLANNIC(_NIC):
    """Representation of a WLAN network interface controller."""
    def __init__(self, devname, mac, is_cached):
        super().__init__(devname, 'wifi', mac, is_cached)

    def add_service(self, service):
        assert isinstance(service, _WLANService)
        super().add_service(service)

    def get_max_age(self):
        return 5 * 60


class _AllNICs:
    """Collection of all NICs in the system, or NICs supposed to be in the
    system."""
    def __init__(self):
        self.lock = RLock()
        self._nics = []
        self._nics_by_service = {}
        self._nics_by_devname = {}
        self._nics_by_mac = {}

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def __iter__(self):
        return iter(self._nics)

    def get_nic_by_service_id(self, service_id):
        with self.lock:
            try:
                return self._nics_by_service[service_id]
            except KeyError:
                pass

    def get_nic_by_mac(self, mac):
        with self.lock:
            try:
                return self._nics_by_mac[mac.upper()]
            except KeyError:
                return None

    def get_nic_by_device_name(self, devname):
        with self.lock:
            try:
                return self._nics_by_devname[devname]
            except KeyError:
                return None

    def _do_add_nic(self, nic):
        self._nics_by_devname[nic.devname] = nic
        self._nics_by_mac[nic.mac] = nic
        self._nics.append(nic)
        return nic

    def add_nic(self, nic):
        assert isinstance(nic, (_EthernetNIC, _WLANNIC))
        assert nic

        with self.lock:
            if not self.get_nic_by_device_name(nic.devname):
                return self._do_add_nic(nic)

        return None

    def add_service(self, service, *, devname=None):
        assert isinstance(service, _Service)

        if devname is not None:
            assert isinstance(devname, str)
            assert devname

        with self.lock:
            tech, mac = service.get_tech_and_mac()
            temp = self.get_nic_by_mac(mac)

            if tech == 'ethernet':
                nic = temp if temp else _EthernetNIC(devname, mac,
                                                     service.is_cached)
            elif tech == 'wifi':
                nic = temp if temp else _WLANNIC(devname, mac,
                                                 service.is_cached)
            else:
                raise TypeError('Unsupported technology "{}"'.format(tech))

            assert nic

            nic.add_service(service)
            self._nics_by_service[service.id] = nic

            if not temp:
                nic = self._do_add_nic(nic)

        return nic


class IPv4ConfigurationSchema(halogen.Schema):
    """Representation of :class:`_IPv4Configuration`."""

    #: IPv4 DHCP method, one of ``auto``, ``dhcp``, ``manual``, or ``off``.
    dhcp_method = halogen.Attr()

    #: IPv4 host address.
    address = halogen.Attr()

    #: IPv4 network mask.
    netmask = halogen.Attr()

    #: IPv4 default gateway address.
    gateway = halogen.Attr()


class IPv6ConfigurationSchema(halogen.Schema):
    """Representation of :class:`_IPv6Configuration`."""

    #: IPv6 DHCP method, one of ``auto``, ``manual``, or ``off``. The value
    #: ``6to4`` can be returned in IPv6 active settings, but it cannot be set
    #: as preference.
    dhcp_method = halogen.Attr()

    #: IPv6 host address.
    address = halogen.Attr()

    #: IPv6 network prefix length.
    prefix_length = halogen.Attr()

    #: IPv6 default gateway address.
    gateway = halogen.Attr()


class ProxyConfigurationSchema(halogen.Schema):
    """Representation of :class:`_ProxyConfiguration`."""

    #: Proxy configuration method, one of ``direct``, ``auto``, or ``manual``.
    method = halogen.Attr()

    #: Automatic proxy configuration URL for ``auto`` method.
    auto_config_pac_url = halogen.Attr()

    #: Array of proxy server URLs.
    proxy_servers = halogen.Attr()

    #: Array of hosts which are accessed directly, not via proxy.
    excluded_hosts = halogen.Attr()


class ServiceConfigSchema(halogen.Schema):
    """Representation of :class:`_ServiceConfiguration`."""

    #: IPv4 settings. See :class:`IPv4ConfigurationSchema`.
    ipv4_config = halogen.Attr(halogen.types.Nullable(IPv4ConfigurationSchema))

    #: IPv6 settings. See :class:`IPv6ConfigurationSchema`.
    ipv6_config = halogen.Attr(halogen.types.Nullable(IPv6ConfigurationSchema))

    #: Proxy settings. See :class:`ProxyConfigurationSchema`.
    proxy_config =\
        halogen.Attr(halogen.types.Nullable(ProxyConfigurationSchema))

    #: List of DNS servers (strings, might be ``null``).
    dns_servers = halogen.Attr()

    #: List of NTP servers (strings, might be ``null``).
    time_servers = halogen.Attr()

    #: List of domain names (strings, might be ``null``).
    domains = halogen.Attr()


class ServiceSchema(halogen.Schema):
    """Representation of :class:`_Service`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/network/services/' + value.id)

    #: ID of the service.
    id = halogen.Attr()

    #: Name of the service (might be SSID as string, might be some other
    #: human-readable name, or might even be ``null`` for WLAN with binary
    #: SSID).
    name = halogen.Attr(attr=lambda value: value.get_name())

    #: State of the services.
    state = halogen.Attr()

    #: Whether or not the service information is cached (possibly outdated).
    is_cached = halogen.Attr()

    #: Whether or not the service is a service defined by the system.
    is_system_service = halogen.Attr()

    #: Whether or not the service was selected by the user.
    is_favorite = halogen.Attr()

    #: Whether or not the service will auto-activate if possible.
    is_auto_connect = halogen.Attr()

    #: Currently configured settings of this service, serialized using
    #: :class:`ServiceConfigSchema`. If this field is not ``null``, then the
    #: service has been activated by the system.
    active_config = halogen.Attr(halogen.types.Nullable(ServiceConfigSchema))

    #: Preconfigured settings used to configure this service if and when it
    #: gets activated. This is an object serialized using
    #: :class:`ServiceConfigSchema`.
    supposed_config = halogen.Attr(ServiceConfigSchema)

    #: Network SSID as hexstring (WLAN only). Use this field for presentation
    #: in case the name is empty.
    ssid = halogen.Attr(attr=lambda value: value.get_ssid(), required=False)

    #: Array of strings of possible security settings for this service
    #: (WLAN only).
    security = halogen.Attr(required=False)

    #: Signal strength (WLAN only).
    strength = halogen.Attr(required=False)

    #: Boolean representing whether or not this service has WPS capability
    #: (WLAN only).
    wps_capability = halogen.Attr(required=False)

    #: Boolean representing whether or not this service has WPS activated
    #: (WLAN only).
    wps_active = halogen.Attr(required=False)


class NICSchema(halogen.Schema):
    """Representation of :class:`_NIC`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/network/interfaces/' + value.mac)

    #: MAC address in human-readable format.
    mac = halogen.Attr(attr=lambda value: value.get_mac_address())

    #: Device name in Linux system.
    devname = halogen.Attr()

    #: Network technology as a string ID.
    technology = halogen.Attr()

    #: Whether or not the NIC information is cached (possibly outdated).
    is_cached = halogen.Attr()

    #: Network services available on this NIC.
    #: This is an array of objects serialized using the :class:`ServiceSchema`.
    services = halogen.Embedded(
        halogen.types.List(ServiceSchema),
        attr=lambda value: value.services.values()
    )

    #: Whether or not this device is a "secondary" device.
    #:
    #: The notion of "primary" and "secondary" device is completely artificial
    #: and imposed only by a fundamental protocol design mistake buried deep
    #: down in the device, between the Streaming Board and the appliance CPU.
    #: This field shows up only in those appliances which are affected by this
    #: design mistake; it will not show up anymore once the protocol gets fixed
    #: or simply falls out of use.
    is_secondary = halogen.Attr(required=False)


class NetworkSchema(halogen.Schema):
    """Representation of :class:`Network`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Airable API entry point.
    interfaces = halogen.Embedded(
        halogen.types.List(NICSchema),
        attr=lambda value: value._all_nics_cache
    )


def _do_put_network_configuration(request, service_id, nic,
                                  is_for_future_service):
    if nic is None:
        raise NotFound()

    # input sanitation
    try:
        config_request = _ServiceConfigurationRequest.from_json(
                                request.json,
                                nic=(nic if is_for_future_service else None),
                                is_wlan=(nic.technology == 'wifi'))
    except Exception as e:
        return jsonify_error(request, log, False, 400,
                             'Exception: ' + str(e))

    request_data = config_request.to_dict_for_dcpd()
    if not request_data:
        return jsonify_error(request, log, False, 400,
                             'Empty configuration request')

    # send configuration request to dcpd
    try:
        iface = strbo.dbus.Interfaces.dcpd_network()
        iface.SetServiceConfiguration(service_id, jsonify_simple(request_data))
    except dbus.exceptions.DBusException as e:
        return jsonify_error(request, log, True, 500,
                             'Exception [dcpd]: ' + e.get_dbus_message(),
                             error='dcpd')

    return Response(status=204)


class Services(Endpoint):
    """**API Endpoint** - Network service information and management.

    +-------------+----------------------------------------------------------+
    | HTTP method | Description                                              |
    +=============+==========================================================+
    | ``GET``     | Return object containing a service properties of network |
    |             | service `{id}`. See :class:`ServiceSchema`.              |
    +-------------+----------------------------------------------------------+
    | ``PUT``     | Set network configuration for the service.               |
    +-------------+----------------------------------------------------------+

    Details on method ``GET``:
        The network services are managed by ConnMan. All information in the
        returned objects are taken directly from ConnMan in condensed form.

        Note that it is *not* possible to read out WLAN passwords. There are
        two reasons for this: (1) deliberate decision based on security
        concerns, and (2) technical limitations (also induced by security
        concerns). Security is an issue here since the REST API is completely
        open, unprotected, and may be accessed from anywhere. This is why we
        cannot spill passwords around. Even if we wanted, ConnMan's settings
        are not readable by non-privileged processes (and the REST API does
        *not* run with root privileges), so there is a technical restriction
        which makes it impossible for the REST API to read out any passwords.

    Details on method ``PUT``:
        The client shall send a JSON object containing the following fields:
            ``supposed_config`` is a non-null object matching
            :class:`ServiceConfigSchema` and is used to pass the desired
            IP configuration and other network configuration parameters. Note
            that all fields should be defined, otherwise undesired default
            values may be filled in.

            ``auto_connect`` is a required field containing one of the string
            values ``no``, ``yes``, or ``now``. The value ``no`` means that the
            network configuration for service `{id}` should only be stored on
            the device, but the service should not be activated. The value
            ``yes`` also requests to store the configuration on the device, and
            in addition tells the network management software to consider the
            service for auto-connection. The value ``now`` is like ``yes``, but
            tries to activate the service immediately. Note that for WPS
            ``auto_connect`` must be set to ``now``, otherwise the request
            wouldn't make any sense.

            ``passphrase`` is a string containing the network passphrase. This
            field is required for WLAN services.

        In case a service is to be configured for which there is no endpoint
        (hidden networks, networks out of reach), a somewhat less comfortable
        and more error-prone configuration via the :class:`Interfaces` endpoint
        is possible as well.

    Any field in a JSON object not listed in the documentation for ``PUT`` will
    be ignored. It is therefore conveniently acceptable for an HTTP client to
    send back the JSON object it got via ``GET``, but with updated settings.
    All the client will have to do in this case is setting the passphrase.
    """

    #: Path to endpoint.
    href = '/network/services/{id}'
    href_for_map = '/network/services/<id>'

    #: Supported HTTP methods.
    methods = ('GET', 'PUT')

    def __init__(self, network_endpoint):
        Endpoint.__init__(self, 'network_services',
                          name='network_service_info',
                          title='Information about a specific network service')
        self.network_endpoint = network_endpoint

    def __call__(self, request, id, **values):
        with self.network_endpoint as ep:
            try:
                if request.method == 'GET':
                    return Services._handle_http_get(request, id, ep)

                with ep.get_all_nics() as nics:
                    nic = nics.get_nic_by_service_id(id)
                    Services._fill_in_wlan_info(nic, id, request.json)
                    return _do_put_network_configuration(request, id,
                                                         nic, False)
            except AttributeError:
                raise NotFound()

    @staticmethod
    def _fill_in_wlan_info(nic, service_id, json):
        service = nic.get_service_by_id(service_id) \
                        if nic.technology == 'wifi' else None

        if service:
            json['wlan_info'] = {
                'security': service.security,
                'ssid': service.get_ssid(),
                'name': service.get_name()
            }
        else:
            json.pop('wlan_info', None)

    @staticmethod
    def _handle_http_get(request, id, ep):
        cached = if_none_match(request, ep.get_etag())
        if cached:
            return cached

        with ep.get_all_nics() as nics:
            nic = nics.get_nic_by_service_id(id)
            service = nic.get_service_by_id(id) if nic else None

            if service is not None:
                return jsonify_e(request, ep.get_etag(),
                                 5 * 60, ServiceSchema.serialize(service))

        raise NotFound()


class Interfaces(Endpoint):
    """**API Endpoint** - Network interface information and management.

    +-------------+-----------------------------------------------------------+
    | HTTP method | Description                                               |
    +=============+===========================================================+
    | ``GET``     | Return object containing information about the network    |
    |             | adapter with MAC address `{mac}`. See :class:`NICSchema`. |
    +-------------+-----------------------------------------------------------+
    | ``PUT``     | Set network configuration for a service.                  |
    +-------------+-----------------------------------------------------------+

    Details on method ``GET``:
        The network adapter is always specified by MAC address in the URL
        path; that is, the adapter's MAC address must be known in order to
        access it. The preferred way to get at MAC addresses and paths to
        individual networking adapter objects is through the :class:`Network`
        endpoint.

    Details on method ``PUT``:
        The client shall send a JSON object containing the following fields:
            ``supposed_config``, ``auto_connect``, ``passphrase``:
            see :class:`Services` endpoint.

            ``wlan_info``: a JSON object which is only required to exist and
            to be non-`null` when sending configuration for a WLAN service.
            This object is used to fill in the missing bits which would
            otherwise be known on server-side when sending configuration to a
            :class:`Services` endpoint. The object must contain the field
            ``security`` to specify the desired security identifier (string).
            Further, the object must contain one of the fields ``name`` or
            ``ssid`` to specify the network name; if both are specified, then
            ``ssid`` takes precedence.

        Note that the primary and preferred way for setting configuration data
        is to ``PUT`` data directly to a service at the :class:`Services`
        endpoint because that way is much less error-prone.

        The method defined here is an alternative way which is required only
        for services not listed in the object returned by the :class:`Network`
        endpoint. Use cases include sending configuration data for hidden WLAN
        networks and for services which do not exist yet, but are known to
        exist in the future. Since parameters must be provided by the client,
        this method is less robust and may easily lead to configuration
        mistakes. If possible, use the :class:`Services` endpoint.
    """

    #: Path to endpoint.
    href = '/network/interfaces/{mac}'
    href_for_map = '/network/interfaces/<mac>'

    #: Supported HTTP methods.
    methods = ('GET', 'PUT')

    def __init__(self, network_endpoint):
        Endpoint.__init__(self, 'network_interfaces',
                          name='network_interface_info',
                          title='Information about a specific NIC')
        self.network_endpoint = network_endpoint

    def __call__(self, request, mac, **values):
        with self.network_endpoint as ep:
            try:
                if request.method == 'GET':
                    return Interfaces._handle_http_get(request, mac, ep)

                with ep.get_all_nics() as nics:
                    nic = nics.get_nic_by_mac(mac)
                    return _do_put_network_configuration(request, '',
                                                         nic, True)
            except AttributeError:
                raise NotFound()

    @staticmethod
    def _handle_http_get(request, mac, ep):
        cached = if_none_match(request, ep.get_etag())
        if cached:
            return cached

        with ep.get_all_nics() as nics:
            nic = nics.get_nic_by_mac(mac)

            if nic is not None:
                return jsonify_e(request, ep.get_etag(),
                                 nic.get_max_age(),
                                 NICSchema.serialize(nic))

        raise NotFound()


def _mk_service_config(config):
    if not config:
        return None

    def get_string_list(src):
        if src is None:
            return None

        if not isinstance(src, list):
            return []

        for elem in src:
            if not isinstance(elem, str):
                return []

        return src

    temp = config.get('ipv4_config', None)

    if temp:
        ipv4_config = _IPv4Configuration(
            temp.get('dhcp_method', None), temp.get('address', None),
            temp.get('netmask', None), temp.get('gateway', None))
    else:
        ipv4_config = None

    temp = config.get('ipv6_config', None)

    if temp:
        ipv6_config = _IPv6Configuration(
            temp.get('dhcp_method', None), temp.get('address', None),
            temp.get('prefix_length', None), temp.get('gateway', None))
    else:
        ipv6_config = None

    temp = config.get('proxy_config', None)

    if temp:
        proxy_config = _ProxyConfiguration(
            temp.get('method', None), temp.get('auto_config_pac_url', None),
            get_string_list(temp.get('proxy_servers', None)),
            get_string_list(temp.get('excluded_hosts', None)))
    else:
        proxy_config = None

    temp = None

    dns_servers = get_string_list(config.get('dns_servers', None))
    time_servers = get_string_list(config.get('time_servers', None))
    domains = get_string_list(config.get('domains', None))

    return _ServiceConfiguration(
        ipv4_config=ipv4_config, ipv6_config=ipv6_config,
        proxy_config=proxy_config, dns_servers=dns_servers,
        time_servers=time_servers, domains=domains)


def _fill_in_data_from_dcpd(all_nics, network_configuration):
    config = loads(network_configuration)

    nics = config.get('nics', None)
    services = config.get('services', None)

    if not nics and not services:
        return False

    if nics:
        for mac in nics.keys():
            nic_info = nics[mac]
            devname = nic_info.get('device_name', None)
            if not devname:
                continue

            tech = nic_info.get('technology', '')
            if tech.lower() == 'ethernet':
                nic = _EthernetNIC(devname, _NIC.parse_mac_address(mac),
                                   nic_info.get('cached', False))
            elif tech.lower() == 'wifi':
                nic = _WLANNIC(devname, _NIC.parse_mac_address(mac),
                               nic_info.get('cached', False))
            else:
                nic = None

            if nic:
                if nic_info.get('is_secondary', False):
                    nic.mark_as_secondary()

                all_nics.add_nic(nic)

    if services:
        for mac in services.keys():
            nic = all_nics.get_nic_by_mac(_NIC.parse_mac_address(mac))
            if not nic:
                continue

            service_infos = services[mac]
            if not service_infos:
                continue

            for service_info in service_infos:
                active_service_configuration =\
                    _mk_service_config(service_info.get('active_config', None))
                supposed_service_configuration =\
                    _mk_service_config(service_info.get('supposed_config',
                                                        None))

                if nic.technology == 'ethernet':
                    service = _EthernetService(
                        service_info['id'],
                        service_info.get('is_favorite', False),
                        service_info.get('is_auto_connect', False),
                        active_service_configuration,
                        supposed_service_configuration,
                        service_info.get('is_system_service', False),
                        service_info.get('cached', False),
                        service_info.get('state', 'unknown')
                    )
                elif nic.technology == 'wifi':
                    service = _WLANService(
                        service_info['id'],
                        service_info.get('is_favorite', False),
                        service_info.get('is_auto_connect', False),
                        active_service_configuration,
                        supposed_service_configuration,
                        service_info.get('is_system_service', False),
                        service_info.get('cached', False),
                        service_info.get('state', 'unknown'),
                        security=service_info.get('security', None),
                        strength=service_info.get('strength', -1),
                        wps_capability=service_info.get('wps_capability',
                                                        False),
                        wps_active=service_info.get('wps_active', False)
                    )
                else:
                    service = None

                if service:
                    all_nics.add_service(service)

    return True


class Network(Endpoint):
    """**API Endpoint** - Network configuration.

    +-------------+-----------------------------------------------------+
    | HTTP method | Description                                         |
    +=============+=====================================================+
    | ``GET``     | Return object containing all networking properties. |
    +-------------+-----------------------------------------------------+

    Details on method ``GET``:
        Returns an object containing a list of network adapters and available
        services on these. All network adapter objects are returned in the
        embedded ``interfaces`` array (see :class:`NICSchema`). Each network
        adapter contains an embedded ``services`` array (see
        :class:`ServiceSchema`).

        The returned data enables clients to obtain a full, consistent, and
        glitch-free view on Streaming Board networking facilities. Links to
        the individual network adapter objects (see also :class:`Interfaces`)
        and to all the service objects (see also :class:`Services`) are
        included so that clients can refer to them if they have to.
    """

    #: Path to endpoint.
    href = '/network'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    _all_nics_cache = None
    _all_nics_etag = None

    def __init__(self):
        Endpoint.__init__(self, 'network_configuration', name='network_config',
                          title='Configuration of network services')
        self.interfaces_endpoint = Interfaces(self)
        self.services_endpoint = Services(self)

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def __call__(self, request, **values):
        with self.lock:
            cached = if_none_match(request, self.get_etag())
            if cached:
                return cached

            try:
                self._refresh()
            except dbus.exceptions.DBusException as e:
                return jsonify_error(
                        request, log, True, 500,
                        'Exception [dcpd]: ' + e.get_dbus_message(),
                        error='dcpd')

            return jsonify_e(request, self.get_etag(), 3 * 60,
                             NetworkSchema.serialize(self))

    def _refresh(self):
        self._all_nics_cache = _AllNICs()
        self._all_nics_etag = None

        iface = strbo.dbus.Interfaces.dcpd_network()
        version, network_configuration = iface.GetAll(
            self._all_nics_etag if self._all_nics_etag is not None else '')

        try:
            if version and _fill_in_data_from_dcpd(self._all_nics_cache,
                                                   network_configuration):
                self._all_nics_etag = version
        except Exception as e:
            log.error('Failed parsing network configuration: {}'.format(e))
            self._all_nics_cache = _AllNICs()

    def get_all_nics(self):
        return self._all_nics_cache

    def get_etag(self):
        return self._all_nics_etag


network_endpoint = Network()
all_endpoints = [
        network_endpoint, network_endpoint.interfaces_endpoint,
        network_endpoint.services_endpoint,
]


def add_endpoints():
    """Register all endpoints defined in this module."""
    register_endpoints(all_endpoints)
