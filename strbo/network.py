#! /usr/bin/env python3 # -*- coding: utf-8 -*-

# Copyright (C) 2018  T+A elektroakustik GmbH & Co. KG
#
# This file is part of StrBo-REST.
#
# StrBo-REST is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 3 as
# published by the Free Software Foundation.
#
# StrBo-REST is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with StrBo-REST.  If not, see <http://www.gnu.org/licenses/>.


from threading import RLock
import halogen

from .endpoint import Endpoint
from .utils import jsonify


def _assert_list_of_strings_or_empty(l):
    if l is None:
        return

    assert isinstance(l, list)

    for elem in l:
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


class _IPv6Configuration(_IPConfiguration):
    """Set of IPv6 configuration settings."""

    def __init__(self, dhcp_method, address, prefix_length, gateway):
        super().__init__(dhcp_method, address, gateway)
        self.prefix_length = prefix_length


class _ProxyConfiguration:
    """Set of proxy configuration settings."""

    def __init__(self, method, pac_url, servers, excludes):
        self.method = method
        self.auto_config_pac_url = pac_url
        self.proxy_servers = servers
        self.excluded_hosts = excludes


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


class _Service:
    """Representation of a generic network service."""
    def __init__(self, service_id, is_favorite, active_config,
                 supposed_config, is_system_service, state):
        assert isinstance(service_id, str)
        assert service_id
        assert isinstance(is_favorite, bool)
        assert isinstance(active_config, (_ServiceConfiguration, type(None)))
        assert isinstance(supposed_config, (_ServiceConfiguration, type(None)))
        assert isinstance(is_system_service, bool)
        assert isinstance(state, str)
        assert state

        self.id = service_id
        self.active_config = active_config
        self.supposed_config = supposed_config
        self.is_system_service = is_system_service
        self.is_favorite = is_favorite
        self.state = state

    def get_tech_and_mac(self):
        tokens = self.id.split('_')
        return (tokens[0], tokens[1])


class _EthernetService(_Service):
    """Representation of an Ethernet network service."""
    def __init__(self, service_id, is_favorite, active_config,
                 supposed_config, is_system_service, state):
        super().__init__(service_id, is_favorite, active_config,
                         supposed_config, is_system_service, state)

    def get_name(self):
        return 'Wired'


class _WLANService(_Service):
    """Representation of a WLAN network service."""
    def __init__(self, service_id, is_favorite, active_config,
                 supposed_config, is_system_service, state, *,
                 security=None, strength=-1,
                 wps_capability=False, wps_active=False):
        _assert_list_of_strings_or_empty(security)
        assert isinstance(strength, int)
        assert isinstance(wps_capability, bool)
        assert isinstance(wps_active, bool)

        super().__init__(service_id, is_favorite, active_config,
                         supposed_config, is_system_service, state)

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
    def __init__(self, devname, technology, mac):
        assert isinstance(devname, str)
        assert devname
        assert isinstance(technology, str)
        assert technology
        assert isinstance(mac, str)
        assert mac

        self.devname = devname
        self.technology = technology
        self.mac = mac
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

    def get_service_by_id(self, id):
        try:
            return self.services[id]
        except KeyError:
            return None

    def get_mac_address(self):
        return ':'.join([
            self.mac[i:i + 2].upper().upper() for i in range(0, 12, 2)])


class _EthernetNIC(_NIC):
    """Representation of an Ethernet network interface controller."""
    def __init__(self, devname, mac):
        super().__init__(devname, 'ethernet', mac)

    def add_service(self, service):
        assert isinstance(service, _EthernetService)
        super().add_service(service)


class _WLANNIC(_NIC):
    """Representation of a WLAN network interface controller."""
    def __init__(self, devname, mac):
        super().__init__(devname, 'wifi', mac)

    def add_service(self, service):
        assert isinstance(service, _WLANService)
        super().add_service(service)


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
                return self._nics_by_mac[mac]
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

    def add_service(self, devname, service):
        assert isinstance(devname, str)
        assert devname
        assert isinstance(service, _Service)

        with self.lock:
            temp = self.get_nic_by_device_name(devname)
            tech, mac = service.get_tech_and_mac()

            if tech == 'ethernet':
                nic = temp if temp else _EthernetNIC(devname, mac)
            elif tech == 'wifi':
                nic = temp if temp else _WLANNIC(devname, mac)
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

    #: Whether or not the service is a service defined by the system.
    is_system_service = halogen.Attr()

    #: Whether or not the service will auto-activate if possible.
    is_favorite = halogen.Attr()

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


class Services(Endpoint):
    """**API Endpoint** - Network service information and management.

    +-------------+----------------------------------------------------------+
    | HTTP method | Description                                              |
    +=============+==========================================================+
    | ``GET``     | Return object containing a service properties of network |
    |             | service `{id}`. See :class:`ServiceSchema`.              |
    +-------------+----------------------------------------------------------+

    Details on method ``GET``:
        The network services are managed by ConnMan. All information in the
        returned objects are taken directly from ConnMan, in condensed form.
    """

    #: Path to endpoint.
    href = '/network/services/{id}'
    href_for_map = '/network/services/<id>'

    #: Supported HTTP methods.
    methods = ('GET',)

    def __init__(self, network_endpoint):
        Endpoint.__init__(self, 'network_services',
                          name='network_service_info',
                          title='Information about a specific network service')
        self.network_endpoint = network_endpoint

    def __call__(self, request, id, **values):
        with self.network_endpoint:
            with self.network_endpoint.get_all_nics() as nics:
                nic = nics.get_nic_by_service_id(id)
                service = nic.get_service_by_id(id) if nic else None

                if service is None:
                    return jsonify(request, {})
                else:
                    return jsonify(request, ServiceSchema.serialize(service))


class Interfaces(Endpoint):
    """**API Endpoint** - Network interface information and management.

    +-------------+-----------------------------------------------------------+
    | HTTP method | Description                                               |
    +=============+===========================================================+
    | ``GET``     | Return object containing information about the network    |
    |             | adapter with MAC address `{mac}`. See :class:`NICSchema`. |
    +-------------+-----------------------------------------------------------+

    Details on method ``GET``:
        The network adapter is always specified by MAC address in the URL
        path; that is, the adapter's MAC address must be known in order to
        access it. The preferred way to get at MAC addresses and paths to
        individual networking adapter objects is through the :class:`Network`
        endpoint.
    """

    #: Path to endpoint.
    href = '/network/interfaces/{mac}'
    href_for_map = '/network/interfaces/<mac>'

    #: Supported HTTP methods.
    methods = ('GET',)

    def __init__(self, network_endpoint):
        Endpoint.__init__(self, 'network_interfaces',
                          name='network_interface_info',
                          title='Information about a specific NIC')
        self.network_endpoint = network_endpoint

    def __call__(self, request, mac, **values):
        with self.network_endpoint:
            with self.network_endpoint.get_all_nics() as nics:
                nic = nics.get_nic_by_mac(mac)

                if nic is None:
                    return jsonify(request, {})
                else:
                    return jsonify(request, NICSchema.serialize(nic))


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
            self._refresh()
            return jsonify(request, NetworkSchema.serialize(self))

    def _clear(self):
        self._all_nics_cache = None

    def _refresh(self):
        self._clear()
        self._all_nics_cache = _AllNICs()

    def get_all_nics(self):
        self._refresh()
        return self._all_nics_cache


network_endpoint = Network()
all_endpoints = [
        network_endpoint, network_endpoint.interfaces_endpoint,
        network_endpoint.services_endpoint,
]


def add_endpoints():
    """Register all endpoints defined in this module."""
    from .endpoint import register_endpoints
    register_endpoints(all_endpoints)
