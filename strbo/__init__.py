#! /usr/bin/env python3
# -*- coding: utf-8 -*-

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

"""This module implements a web-based interface to the T+A Streaming Board, the
*Streaming Board REST API*.

Clients of this API are supposed to communicate with the Streaming Board using
standard HTTP requests, and to allow themselves to be guided by hyperlinks and
HTTP responses. The web API exposed by this module strives to be a RESTful one,
i.e.,

* it makes heavy use of HTTP methodologies in the role of an HTTP server;
* API calls are *always* stateless;
* the API is discoverable and more or less self-documenting;
* caching of responses is explicitly supported; and
* it obeys to HATEOAS principles.

There is a single API entry point defined in :class:`strbo.rest.EntryPoint`
(note, however, that the web server which handles the HTTP traffic may add a
prefix to this path or may mangle it in other ways). All other URLs found in
the documentation are defined relative to this entry point.

The API has only a single entry point and is designed to be discoverable, so is
this documentation. Documentation is linked in a similar way as the API is
linked with hyperlinks. It is actually possible to find full endpoint
documentation for all endpoints by following the links in this documentation,
starting at its entry point :class:`strbo.rest.EntryPoint`. (Full text search
may also serve you well.)
"""


monitor = None
app = None


def init(path_to_helpers):
    """Initialize this module.

    Must be called before doing any with the :mod:`strbo` module.
    """
    from .external import register_helpers
    register_helpers(path_to_helpers)

    from .monitor import Monitor
    global monitor
    monitor = Monitor()

    # create the shared D-Bus instance
    from .dbus import Bus
    Bus()

    from .rest import StrBo
    global app
    app = StrBo()
