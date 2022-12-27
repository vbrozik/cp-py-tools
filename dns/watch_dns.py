#!/usr/bin/env python3

"""Watch DNS resolution.

Requires:
    Python 3.7+

Tested on:
    Check Point Gaia R80.30+

Installation:
    - by pasting file content
    mkdir -p bin/lib_python/vbc
    cat >bin/watch_dns.py
    cat >bin/lib_python/vbc/dns.py
    cat >bin/lib_python/vbc/subprocess_ext.py

Usage:
    nohup python3 watch_dns.py watched.url &
    cd /var/log/watch_dns/
    less -S +F $(printf %s\\n watch_dns_base*.log | tail -1)
    less -S +F $(printf %s\\n watch_dns_cmd*.log | tail -1)
    less -S +F $(printf %s\\n watch_dns_cpdom*.log | tail -1)

Notes:
    On R80.30 domains_tool -d sometimes fail with status code 1 and
    the following message on stdout (with typo "erorr"):
    Internal erorr, for more information use DEBUG mode
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import os
import pathlib
import re
import string
import sys
import time
from typing import IO, NoReturn, Sequence

DEFAULT_INTERVAL = 5
DEFAULT_LOG_DIR = '/var/log/watch_dns'
"""Directory where to put logs. Will be created if it does not exist."""
DEFAULT_LOG = DEFAULT_LOG_DIR + '/watch_dns_base_${date_time}.log'
"""Basic logs - dig and A record changes, missing IP addresses in CP's domains_tool."""
DEFAULT_LOG_CP_DOMAINS = DEFAULT_LOG_DIR + '/watch_dns_cpdom_${date_time}.log'
"""Output of domains_tool when parsing fails."""
DEFAULT_LOG_COMMANDS = DEFAULT_LOG_DIR + '/watch_dns_cmd_${date_time}.log'
"""Output of commands when IP addresses are missing in CP's domains_tool."""
CP_DOMAINS_REPEAT_INTERVAL = 0.5    # repeat interval for domains_tool attempts
"""Repeat interval for attempts when domains_tool fails with an internal error."""

CLI_TOOLS_ENCODING = sys.getdefaultencoding()   # probably wrong, TODO test on Windows
NULL_TIME = datetime.datetime(1, 1, 1)

lib_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib_python')
sys.path.insert(0, lib_dir)

# pylint: disable=wrong-import-position
from vbc.dns import DNSResult, dig_simple  # noqa: E402
from vbc.subprocess_ext import AuditedRun  # noqa: E402


class LatestUnique(list):
    """Store unique values like a set but sorted by latest appearance."""
    def add(self, value) -> int:
        """Add a value - like set.add() but the new value will be sorted first.

        Returns:
            Number of the first entries changed.
        """
        try:
            index = self.index(value)
        except ValueError:
            self.insert(0, value)
            return len(self)
        self.insert(0, self.pop(index))
        return index + 1

    def add_multi(self, value_list) -> int:
        """Add multiple values, return the biggest change."""
        return max(self.add(value) for value in value_list)


class LogData:
    """Logging data like open files etc."""
    file_name: str
    file_cp_dom_name: str
    file_cmd_name: str

    file_stack: contextlib.ExitStack
    file: IO[str]
    """Basic log."""
    file_cp_dom: IO[str]
    """Failed Check Point domains_tool log."""
    file_cmd: IO[str]
    """Command output log."""

    txt_time_stamp: str
    """Text timestamp for logging."""
    run_list: list[AuditedRun]
    """List of outputs of executed commands."""

    def __init__(
            self, file_name: str, file_cp_dom_name: str, file_cmd_name: str) -> None:
        self.file_stack = contextlib.ExitStack()
        self.file_name = file_name
        self.file_cp_dom_name = file_cp_dom_name
        self.file_cmd_name = file_cmd_name

    def __enter__(self) -> LogData:
        self.file = self.file_stack.enter_context(
                        open(self.file_name, 'a', encoding='utf-8'))
        self.file_cp_dom = self.file_stack.enter_context(
                        open(self.file_cp_dom_name, 'a', encoding='utf-8'))
        self.file_cmd = self.file_stack.enter_context(
                        open(self.file_cmd_name, 'a', encoding='utf-8'))
        return self

    def __exit__(self, *_args) -> None:
        self.file_stack.close()

    def set_timestamp(self, date_time: datetime.datetime) -> None:
        """Sets text timestamp for logging. Uses local time zone."""
        self.txt_time_stamp = date_time.astimezone().isoformat(timespec="seconds")


def cp_domains_parse(command_output: str, header: str) -> tuple[list[str], bool]:
    """Parse output of Check Point domains_tool.

    Returns: list of values as strings, boolean success of parsing

    Todo:
        * Match end of table?
    """
    def is_separator(line: str) -> bool:
        return bool(re.match(r'-{10}', line))

    result: list[str] = []
    output_lines = iter(command_output.splitlines())
    if not is_separator(next(output_lines, '')):
        return result, False
    header_re = re.escape(header)
    in_body = False
    for line in output_lines:
        if not in_body:
            if re.match(fr'\|\s+{header_re}\s+', line):
                if not is_separator(next(output_lines, '')):
                    return result, False
                in_body = True
            continue
        match = re.match(r'\|\s(?P<value>\S+)\s+|', line)
        if match and match['value']:
            result.append(match['value'])
    return result, True


def cp_domains_get_addresses(
        domain: str, args: argparse.Namespace) -> tuple[set[str], bool, AuditedRun]:
    """Get list of IP addresses for a domain from CP domains_tool."""
    iteration = 0
    for iteration in range(1, args.repeat_dd + 2):
        command_output = AuditedRun.run(
                ('domains_tool', '-d', domain), encoding=CLI_TOOLS_ENCODING)
        if not (
                command_output.returncode
                and command_output.stdout.lstrip().lower().startswith('internal er')):
            break
        time.sleep(CP_DOMAINS_REPEAT_INTERVAL)
    command_output.iterations = iteration
    result, success = cp_domains_parse(command_output.stdout, 'IP address')
    return set(result), success, command_output


def cp_domains_get_domains(address: str) -> tuple[set[str], bool, AuditedRun]:
    """Get list of domains for an IP address from CP domains_tool."""
    command_output = AuditedRun.run(
            ('domains_tool', '-ip', address), encoding=CLI_TOOLS_ENCODING)
    result, success = cp_domains_parse(command_output.stdout, 'Domain name')
    return set(result), success, command_output


def str_dict(dictionary: dict) -> str:
    """Dictionary to string."""
    return ', '.join(
            f'{key}: {value}'
            for key, value in dictionary.items())


def check_a_records(
        dig_a_records: list[str], cp_addresses: set[str], dig_ip_mru: LatestUnique,
        log_data: LogData, args: argparse.Namespace) -> bool:
    """Check A records obtained from dig.

    Returns: True if commands should be logged.
    """
    changes = dig_ip_mru.add_multi(dig_a_records)
    log_commands = False
    if changes > 2:
        print(
                f'{log_data.txt_time_stamp} '
                f'[dig_{changes}]    latest IPs: {dig_ip_mru}',
                file=log_data.file)
    if not set(dig_a_records) <= cp_addresses:
        print(
                f'{log_data.txt_time_stamp} '
                f'[miss_ip]  dig: {dig_a_records}\tcp: {cp_addresses}',
                file=log_data.file)
        log_commands = True
    for dig_ip in dig_a_records:
        cp_domains, success, command_output = cp_domains_get_domains(dig_ip)
        log_data.run_list.append(command_output)
        if args.name not in cp_domains:
            print(
                    f'{log_data.txt_time_stamp} '
                    f'[miss_dom] {dig_ip} resolves to {cp_domains}',
                    file=log_data.file)
            log_commands = True
        if not success:
            command_output.log(log_data.file_cp_dom)
    return log_commands


def monitor_loop(log_data: LogData, args: argparse.Namespace) -> NoReturn:
    """Perform the infinite DNS monitoring loop."""
    last_dig_result = DNSResult()
    last_cp_addresses: set[str] = set()
    dig_ip_mru = LatestUnique()
    while True:
        log_commands = False
        dig_result = dig_simple(args.name)
        log_data.run_list = [dig_result.dig_run]
        dig_changed = last_dig_result.changed(dig_result)
        log_data.set_timestamp(dig_result.dig_run.start_time)
        if dig_changed:
            print(
                    f'{log_data.txt_time_stamp} [dig]      {str_dict(dig_changed)}',
                    file=log_data.file)
        cp_addresses, success, command_output = cp_domains_get_addresses(
                args.name, args)
        log_data.run_list.append(command_output)
        if not success:     # output parsing failure
            command_output.log(log_data.file_cp_dom)
        if not cp_addresses and command_output.returncode:
            print(
                    f'{log_data.txt_time_stamp} [cp-d]     {cp_addresses}; '
                    f'fail_status: {command_output.returncode}; '
                    f'attempts: {command_output.iterations}; '
                    f'output: {command_output.get_first_line()}',
                    file=log_data.file)
        elif cp_addresses != last_cp_addresses:
            print(
                    f'{log_data.txt_time_stamp} [cp-d]     {cp_addresses}',
                    file=log_data.file)
        dig_a_records = dig_result.get_records('A')
        if dig_a_records:
            log_commands = (
                log_commands or check_a_records(
                        dig_a_records, cp_addresses, dig_ip_mru, log_data, args))
        else:
            print(
                    f'{log_data.txt_time_stamp} [dig]      no A records!',
                    file=log_data.file)
        if log_commands:
            for audited_run in log_data.run_list:
                audited_run.log(log_data.file_cmd)
            print(f'{"#"*80}\n', file=log_data.file_cmd, flush=True)
        log_data.file.flush()
        log_data.file_cp_dom.flush()
        last_dig_result = dig_result
        last_cp_addresses = cp_addresses
        time.sleep(args.interval)


def main(argv: Sequence[str]):
    """Provide CLI interface."""
    parser = argparse.ArgumentParser(
        description='watch DNS resolution changes in time')
    parser.add_argument(
        'name', help='DNS name to watch')
    parser.add_argument(
        '-i', '--interval', type=float, default=DEFAULT_INTERVAL,
        help='the interval to check the DNS resolution')
    parser.add_argument(
        '-r', '--repeat-dd', type=int, default=0,
        help='how many times repeat domains_tool -d when it fails')
    args = parser.parse_args(argv)
    pathlib.Path(DEFAULT_LOG_DIR).mkdir(exist_ok=True)
    log_file_name_params = {
            'date_time': datetime.datetime.now().strftime('%Y%m%d_%H%M')}
    with LogData(
            string.Template(DEFAULT_LOG).substitute(log_file_name_params),
            string.Template(DEFAULT_LOG_CP_DOMAINS).substitute(log_file_name_params),
            string.Template(DEFAULT_LOG_COMMANDS).substitute(log_file_name_params)
            ) as log_data:
        monitor_loop(log_data, args)


if __name__ == '__main__':
    main(sys.argv[1:])
