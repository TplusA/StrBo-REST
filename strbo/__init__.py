#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from .rest import EntryPoint, StrBo
from .endpoint import Endpoint, register_endpoint

register_endpoint(EntryPoint())

from .recovery import add_endpoints as add_recovery_endpoints
add_recovery_endpoints()

app = StrBo()
