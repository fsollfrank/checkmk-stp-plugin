#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

from .agent_based_api.v1 import *

def parse_stp(string_table):
    section = []
    for i in range(len(string_table[0])):
        for x in range(len(string_table[2])):
            if string_table[1][i][1] == string_table[2][x][0]:
                string_table[0][i][0] = string_table[2][x][1]
    for item in string_table[0]:
         section.append(item)
    return section

register.snmp_section(
    name="stp",
    detect=exists(".1.3.6.1.2.1.17.2.15.1.1.1"),
    parse_function=parse_stp,
    fetch=[
        SNMPTree( #string_table[0] -> main snmp variables
            base=".1.3.6.1.2.1.17.2.15.1",
            oids=[
                "1", # STP Port number
                "2", # STP Port Priority
                "3", # STP Status
                "4", # STP Port Enable
                "5", # STP Designated Root
            ]),
        SNMPTree( #string_table[1] -> Bridge Port to Interface ID
            base=".1.3.6.1.2.1.17.1.4.1",
            oids=[
                "1", # Bridge Port number
                "2", # Interface Index
            ]),
        SNMPTree( #string_table[2] -> Interface ID to Interface Name
            base=".1.3.6.1.2.1.2.2.1",
            oids=[
                "1", # Interface Index
                "2", # Interface Name
            ]
        )
    ],
)

def discover_stp(section):
    for line in section:
        yield Service(item=line[0])

def check_stp(item,section):
    for line in section:
        if line[0] == item:
            if line[2] == "1":
                yield Result(state=State.WARN, summary="Port is in disabled state")
            elif line[2] == "2":
                yield Result(state=State.CRIT, summary="Port is in blocking state")
            elif line[2] == "3":
                yield Result(state=State.OK, summary="Port is in listening state")
            elif line[2] == "4":
                yield Result(state=State.OK, summary="Port is in learning state")
            elif line[2] == "5":
                yield Result(state=State.OK, summary="Port is in forwarding state")
            elif line[2] == "6":
                yield Result(state=State.CRIT, summary="Port is in broken state")
            else:
                yield Result(state=State.UNKNOWN, summary="Port is in unknown state")
    return

register.check_plugin(
    name='stp',
    service_name="STP Port Status %s",
    discovery_function=discover_stp,
    check_function=check_stp,
)