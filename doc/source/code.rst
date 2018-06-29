Documentation for Streaming Board REST API implementation and its endpoints
***************************************************************************


Introduction
============

.. automodule:: strbo

How users of the API should read endpoint documentation
-------------------------------------------------------

Each API endpoint---some URL, plainly spoken---has a representation in the code
documented by this documentation. They are instances of classes derived from
the :class:`strbo.endpoint.Endpoint` base class. The
:class:`strbo.rest.EntryPoint` class is an example for such a class, and
:class:`strbo.airable.Info` is another one.

Two kinds of information are required to make use of an endpoint: how to send
requests, and how to interpret the response data.

Request documentation
~~~~~~~~~~~~~~~~~~~~~

By convention adapted in this documentation, the description of each such
endpoint class begins with the words "**API endpoint**" followed by a few words
summarizing the purpose of the endpoint. Thus, all endpoints can also be found
by searching the documentation for "API endpoint". Classes not marked with
these words may be safely ignored unless referenced from endpoint
documentation.

Full class documentation of public members and methods follows for each
endpoint class, including a summary table of permissible HTTP methods a client
may use on the endpoint, and any extra documentation a client may need to use
the endpoint. This should be the primary source of information for developers
of Streaming Board API clients when writing code for setting of API requests.
The HTTP status codes are also documented in this place, and sometimes also the
response data.

The path to an endpoint is found in the **href** member of each endpoint class.
The technically enforced restriction on usable HTTP methods is found in the
**methods** member. Its content should match the table of HTTP methods found in
each endpoint class documentation.

Response data documentation
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The data sent with responses are usually JSON objects (but always make sure the
content type says so). These objects are documented either as a *schema*, by
textual description in the request documentation, or by the JSON object itself
(in case it is trivial).

Often, an endpoint will define one or more schema classes, derived from the
:class:`halogen.schema.Schema` class from the :mod:`halogen` module (HAL+JSON
package). These schema classes determine which fields will be written to the
various JSON objects sent to clients (this information can be seen in the
documentation), and how they are filled in (not in documentation, can only be
seen in source code).

For instance, the :class:`strbo.rest.EntryPoint` endpoint defines the
:class:`strbo.rest.EntryPoint.Schema` schema, and the
:class:`strbo.airable.Services` endpoint defines the schemas
:class:`strbo.airable.Services.Schema` and
:class:`strbo.airable.Services.SchemaShort` (a partial view on this resource
used when embedding it into other responses). And there is, for instance, no
schema defined for the :class:`strbo.airable.Auth` endpoint because the output
is simplistic and self-explanatory; you are supposed to take a look at a
response and to make sense of what you see in such cases (please contact the
author of this software if you think some important bits of information are
missing and should be documented in some way).

Schemas are usually only defined for persistent objects or resources for which
a formal schema definition seems to make sense, not for temporary or
self-explanatory objects created on the fly. The distinction whether or not a
schema should be used for a particular kind of JSON object is arbitrary and to
be considered an implementation detail. Deal with it.


Public API endpoints
====================

Main API entry point
--------------------

.. automodule:: strbo.rest
   :members:

Airable
-------

.. automodule:: strbo.airable
   :members:

Recovery system management
--------------------------

.. automodule:: strbo.recovery
   :members:


Internals
=========

Endpoints
---------

.. automodule:: strbo.endpoint
   :members:

Event monitoring and propagation
--------------------------------

.. automodule:: strbo.monitor
   :members:

D-Bus connection
----------------

.. automodule:: strbo.dbus
   :members:

Utilities and miscellaneous
---------------------------

.. automodule:: strbo.utils
   :members:

.. automodule:: strbo.listerrors
   :members: