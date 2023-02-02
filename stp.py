#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# (c) 2018 Heinlein Support GmbH
#          Robert Sander <r.sander@heinlein-support.de>

# This is free software;  you can redistribute it and/or modify it
# under the  terms of the  GNU General Public License  as published by
# the Free Software Foundation in version 2.  check_mk is  distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
# out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
# PARTICULAR PURPOSE. See the  GNU General Public License for more de-
# tails. You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.

from .agent_based_api.v1 import *

def parse_stp(string_table):
    section = []
    for line in string_table:
        for item in line:
            section.append(item)
    return section

register.snmp_section(
    name="stp",
    detect=exists(".1.3.6.1.2.1.17.2.15.1.1.1"),
    parse_function=parse_stp,
    fetch=[
        SNMPTree(
            base=".1.3.6.1.2.1.17.2.15.1",
            oids=[
                "1", # STP Port number
                "2", # STP Port Priority
                "3", # STP Status
                "4", # STP Port Enable
                "5", # STP Designated Root
            ]),
    ],
)

def discover_stp(section):
    for line in section:
        yield Service(item=line[0])

def check_stp(item,section):
    for line in section:
        if line[0] == item:
            if line[2] != "2":
                yield Result(state=State.OK, summary="Port is not in blocking state")
            if line[2] == "2":
                yield Result(state=State.CRIT, summary="Port is in blocking state")
    return

register.check_plugin(
    name='stp',
    service_name="STP Port Status %s",
    discovery_function=discover_stp,
    check_function=check_stp,
)