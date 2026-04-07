# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Wingmen Solutions ApS
# This file is part of wingpy, distributed under the terms of the GNU GPLv3.
# See the LICENSE, NOTICE, and AUTHORS files for more information.

from importlib import metadata

from wingpy.base import RestApiBaseClass
from wingpy.cisco import (
    CiscoAPIC,
    CiscoCatalystCenter,
    CiscoFMC,
    CiscoHyperfabric,
    CiscoISE,
    CiscoMerakiDashboard,
    CiscoModelingLabs,
    CiscoNexusDashboard,
    CiscoVmanage,
    SplunkEnterprise,
)
from wingpy.generic import GenericRESTAPI
from wingpy.logger import log_to_file, set_logging_level
from wingpy.nsot import Nautobot, NetBox
from wingpy.response import ResponseMapping, ResponseSequence, XMLResponseMapping

__version__ = metadata.version("wingpy")

__all__ = [
    "CiscoAPIC",
    "CiscoCatalystCenter",
    "CiscoFMC",
    "CiscoISE",
    "CiscoHyperfabric",
    "CiscoMerakiDashboard",
    "CiscoModelingLabs",
    "CiscoNexusDashboard",
    "CiscoVmanage",
    "SplunkEnterprise",
    "log_to_file",
    "GenericRESTAPI",
    "Nautobot",
    "NetBox",
    "ResponseMapping",
    "ResponseSequence",
    "RestApiBaseClass",
    "set_logging_level",
    "XMLResponseMapping",
]
