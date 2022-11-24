#!/usr/bin/python3
"""Test Check Point VSX cluster connectivity over all interfaces.

Requirements: Python 3.8+
"""

from __future__ import annotations

import re
import inspect
import sys
import dataclasses
import logging
import argparse
import contextlib

from typing import Optional, NewType, Dict, NamedTuple, Sequence, TextIO


@dataclasses.dataclass
class Interface:
    """Store network interface information."""

    name: str
    status: set[str] = dataclasses.field(default_factory=set)
    ipv4addr: Optional[str] = None
    ipv4masklen: Optional[int] = None
    ethaddr: Optional[str] = None
    vsid: Optional[int] = None
    vsxhost: Optional[str] = None
    arping: bool = True
    failure: bool = False


class VSXDestinations(NamedTuple):
    """Interface ping destinations."""

    vsxsrc: str
    vsxdsts: tuple[str, ...]


# Container for interfaces organized: VSXhost -> VSID -> ifname -> interface
AllInterfaces = NewType(
                'AllInterfaces', Dict[str, Dict[int, Dict[str, Interface]]])


# Container for interfaces organized: VSID -> ifname -> VSXhost -> interface
InterfacesByVSID = NewType(
                'InterfacesByVSID', Dict[int, Dict[str, Dict[str, Interface]]])


@dataclasses.dataclass
class Config:
    """Configuration parameters."""

    show_only_errors = True
    # do not show successful pings
    arping_num = 2
    # number of pings to a single destination
    diag_listings = False
    # enable diagnostic outputs
    batch_ping = True
    # pings from a VSX instance in single line
    ping_from_outside: Optional[bool] = None
    # prepare pings to all VSX members


NL = '\n'   # newline for f-string expressions


sh_get_vsids = inspect.cleandoc(r'''
    ###### list interfaces in all VS
    sleep 1 ; printf '\n\n\n### ' ; vsx stat | grep ^Name: ; \
    vsids="$(vsx stat -l | sed -n 's/^VSID: \+\([0-9]\+\).*$/\1/p')" ; \
    for vs in $vsids ; do \
        printf '### vsenv %s\n' "$vs" ; vsenv "$vs" ; ip addr ; \
    done ; vsenv 0 ; echo "### VSX end" ; \
    ###### ------
    ''')


def collect_interfaces(in_file: Optional[TextIO] = None) -> AllInterfaces:
    """Collect interfaces from shell code run on individual VSX nodes.

    Procedure:
        * A shell code is shown.
        * The user runs it on individual VSX nodes. (in expert mode)
        * The user copies the output from alle the VSX nodes back as the input
            for this function. It is preferred to store this output to a text
            file to be able to reuse it easily.
        * The function parses the information from the text
            to the AllInterfaces data structure.
    """
    if in_file is None:
        in_file = sys.stdin
    if in_file.isatty():
        print("# Run the following code on all the cluster nodes:\n")
        print(sh_get_vsids)
        print(
                "\n"
                "# Now paste the outputs from the individual nodes, "
                "finish by Enter:")
    outputs: AllInterfaces = {}
    host = ''
    vsid = -1
    ifname = ''
    while True:
        line = in_file.readline().rstrip()
        if re.match(r'^(> |\[Expert@)', line):
            continue
        if (
                (match := re.match(r'^### Name:\s+(?P<hostname>.+)', line))
                and (host := match.group('hostname'))):
            outputs[host] = {}
            continue
        if not host:
            if not line:
                break
            logging.critical(
                    "Missing line containing: '### Name:' "
                    "Please restart and paste the complete output.")
            exit(1)
        if re.match(r'^### VSX end', line):
            host = ''
            vsid = -1
            continue
        if (
                (match := re.match(r'^### vsenv\s+(?P<vsid>[0-9]+)', line))
                and (_vsid := match.group('vsid'))):
            vsid = int(_vsid)
            outputs[host][vsid] = {}
            continue
        if vsid < 0:
            logging.critical(
                    "Missing line containing: '### vsenv' "
                    "Please restart and paste the complete output.")
            exit(1)
        if (
                (match := re.match(
                    r'^[0-9]+:\s+(?P<ifname>[0-9a-zA-Z.-]+)'
                    r'.*\s<(?P<status>[^>]*)>', line))
                and (ifname := match.group('ifname'))):
            outputs[host][vsid][ifname] = Interface(
                name=ifname, status=set(match.group('status').split(',')),
                vsid=vsid, vsxhost=host)
            continue
        if match := re.search(
                    r'\slink/ether\s+(?P<ethaddr>[0-9a-fA-F:]+)\s', line):
            assert ifname
            outputs[host][vsid][ifname].ethaddr = (
                    match.group('ethaddr').lower())
            continue
        if match := re.search(
                    r'\sinet\s+(?P<ipv4addr>[0-9.]+)'
                    r'/(?P<ipv4masklen>[0-9]+)\s', line):
            assert ifname
            outputs[host][vsid][ifname].ipv4addr = match.group('ipv4addr')
            outputs[host][vsid][ifname].ipv4masklen = (
                    int(match.group('ipv4masklen')))
            continue
    return outputs


def print_interfaces(interfaces: AllInterfaces, only_arping: bool = True):
    """Print interfaces."""
    indent = '  '
    for hostname, host in interfaces.items():
        print(hostname)
        for vsid, vs in host.items():
            print(f"{indent}{vsid}")
            for ifname, interface in vs.items():
                if not only_arping or interface.arping:
                    print(
                            f"{indent*2}{ifname} "
                            f"{interface.ipv4addr}/{interface.ipv4masklen}")


def iterate_interfaces(interfaces: AllInterfaces):
    """Iterate all interfaces."""
    for host in interfaces.values():
        for vs in host.values():
            yield from vs.values()


def print_interfaces_flat(interfaces: AllInterfaces):
    """Print interfaces."""
    for interface in iterate_interfaces(interfaces):
        print(interface)


def analyze_interfaces(interfaces: AllInterfaces):
    """Analyze interfaces.

    Detect possible problems. Decide which interfaces to test by arping.
    """
    for interface in iterate_interfaces(interfaces):
        if (
                interface.name == 'lo'
                or not interface.ipv4addr):
            interface.arping = False
        if interface.arping and 'LOWER_UP' not in interface.status:
            logging.warn("Interface %s has no link.", interface.name)
            interface.failure = True
            interface.arping = False


def reindex_interfaces_by_vsid(interfaces: AllInterfaces) -> InterfacesByVSID:
    """Reindex interfaces by VSID."""
    intf_by_vsid: InterfacesByVSID = {}
    for intf in iterate_interfaces(interfaces):
        if intf.vsid not in intf_by_vsid:
            intf_by_vsid[intf.vsid] = {}
        if intf.name not in intf_by_vsid[intf.vsid]:
            intf_by_vsid[intf.vsid][intf.name] = {}
        intf_by_vsid[intf.vsid][intf.name][intf.vsxhost] = intf
    return intf_by_vsid


def get_ping_destinations(interfaces: AllInterfaces) -> list[VSXDestinations]:
    """Get VSXhost source and ping destinations."""
    destinations: list[VSXDestinations] = []
    if interfaces:
        destinations.append(VSXDestinations('OutsideOfVSX', tuple(interfaces)))
        for srcVSX in interfaces:
            single_destinations = set(interfaces)
            single_destinations.remove(srcVSX)
            destinations.append(
                    VSXDestinations(srcVSX, tuple(single_destinations)))
    return destinations


def print_arpings(
        intf_by_vsid: InterfacesByVSID,
        ping_destinations: Sequence[VSXDestinations],
        config: Config):
    """Print arping commands."""
    ping_from_outside = config.ping_from_outside
    if ping_from_outside is None:
        ping_from_outside = len(ping_destinations) <= 1
    success_echo_msg = (
        ('#' + ' '*60 + r'\r') if config.show_only_errors else
        (r'# arping $ifip \tok\n'))
    print("# Paste the following code to individual VSX nodes.")
    print(
        "# Single line of code tests connectivity from a single "
        "VS instance on a VSX node.")
    for src in ping_destinations:
        if src.vsxsrc == 'OutsideOfVSX' and not ping_from_outside:
            continue
        print(f"### ====== Pinging from {src.vsxsrc} ======")
        for vsid, intfs in intf_by_vsid.items():
            print(f"### Pinging in VS {vsid}")
            print(f"vsenv {vsid}", end='')
            if config.batch_ping:
                print(" ; c=1 ; for ifip in ", end='')
            else:
                print()
            for intf_name, intf in intfs.items():
                for dsthost in src.vsxdsts:
                    if intf[dsthost].arping:
                        if config.batch_ping:
                            print(
                                f"{intf_name},{dsthost},"
                                f"{intf[dsthost].ipv4addr} ",
                                end='')
                        else:
                            print(
                                f"arping -c{config.arping_num} -I{intf_name} "
                                f"{intf[dsthost].ipv4addr} "
                                f"# dsthost: {dsthost}")
            if config.batch_ping:
                print(
                    '; '
                    'do '
                    'printf "# %02d ... %-48s%20s\\r" "$c" "$ifip" "" ; '
                    'if '
                    f'arping -q -c{config.arping_num} '
                    '-I"${ifip%%,*}" "${ifip##*,}" ; '
                    f'then echo -ne "{success_echo_msg}" ; '
                    'else echo -e "# arping $ifip   \\t\\t* * * FAIL * * *" ; '
                    'fi ; '
                    'c=$((c+1)) ; '
                    'done ; '
                    'printf "%70s\n" ""')
            print()
        print()


def main():
    """Provide CLI interface."""
    # --- CLI interface
    parser = argparse.ArgumentParser()
    parser.add_argument(
            'in_file', nargs='?', type=argparse.FileType('r'),
            help="input file containing concatenated outputs of the helper "
            "shell script run on individual VSX nodes")
    args = parser.parse_args()
    config = Config()
    # --- file input
    with contextlib.ExitStack() as in_file_stack:
        interfaces = collect_interfaces(
                    in_file_stack.enter_context(args.in_file) if args.in_file
                    else None)
    # --- processing and output
    analyze_interfaces(interfaces)
    intf_by_vsid = reindex_interfaces_by_vsid(interfaces)
    ping_destinations = get_ping_destinations(interfaces)
    # print_interfaces(interfaces)
    # exit(0)
    if config.diag_listings:
        print_interfaces_flat(interfaces)
        print(ping_destinations)
    print_arpings(intf_by_vsid, ping_destinations, config)


if __name__ == '__main__':
    main()
