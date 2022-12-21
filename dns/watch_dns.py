#!/usr/bin/env python3

"""Watch DNS resolution.

Requires:
    Python 3.7+

Tested on:
    Check Point Gaia R80.30+

Usage:
    nohup python3 watch_dns.py watched.url &
"""

from __future__ import annotations

import argparse
import datetime
import os
import pathlib
import re
import string
import subprocess
import sys
import time
from typing import IO, NoReturn, Sequence

DEFAULT_INTERVAL = 5
DEFAULT_LOG_DIR = '/var/log/watch_dns'
DEFAULT_LOG = DEFAULT_LOG_DIR + '/watch_dns_${date_time}.log'
DEFAULT_LOG_CP_DOMAINS = DEFAULT_LOG_DIR + '/watch_dns_cpdom_${date_time}.log'

CLI_TOOLS_ENCODING = sys.getdefaultencoding()   # probably wrong, TODO test on Windows
NULL_TIME = datetime.datetime(1, 1, 1)

lib_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib_python')
sys.path.insert(0, lib_dir)

# pylint: disable=wrong-import-position
from vbc.dns import DNSResult, dig_simple  # noqa: E402


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
                    # raise ValueError("domains_tool no separator below header")
                in_body = True
            continue
        match = re.match(r'\|\s(?P<value>\S+)\s+|', line)
        if match and match['value']:
            result.append(match['value'])
    return result, True


def cp_domains_get_addresses(domain: str) -> tuple[set[str], str]:
    """Get list of IP addresses for a domain from CP domains_tool."""
    command_output = subprocess.run(
            ('domains_tool', '-d', domain),
            capture_output=True, encoding=CLI_TOOLS_ENCODING, check=False)
    result, success = cp_domains_parse(command_output.stdout, 'IP address')
    return set(result), (
            command_output.stderr + command_output.stdout
            if not success or command_output.returncode else '')


def cp_domains_get_domains(address: str) -> tuple[set[str], str]:
    """Get list of domains for an IP address from CP domains_tool."""
    command_output = subprocess.run(
            ('domains_tool', '-ip', address),
            capture_output=True, encoding=CLI_TOOLS_ENCODING, check=False)
    result, success = cp_domains_parse(command_output.stdout, 'Domain name')
    return set(result), (
            command_output.stderr + command_output.stdout
            if not success or command_output.returncode else '')


def str_dict(dictionary: dict) -> str:
    """Dictionary to string."""
    return ', '.join(
            f'{key}: {value}'
            for key, value in dictionary.items())


def check_a_records(
        dig_a_records: list[str], cp_addresses: set[str], txt_time_stamp: str,
        dig_ip_mru: LatestUnique, log_file: IO[str], log_file_cp_dom: IO[str],
        args: argparse.Namespace) -> None:
    """Check A records obtained from dig."""
    changes = dig_ip_mru.add_multi(dig_a_records)
    if changes > 2:
        print(
                f'{txt_time_stamp} '
                f'[dig_{changes}]    latest IPs: {dig_ip_mru}',
                file=log_file)
    if not set(dig_a_records) <= cp_addresses:
        print(
                f'{txt_time_stamp} '
                f'[miss_ip]  dig: {dig_a_records}\tcp: {cp_addresses}',
                file=log_file)
    for dig_ip in dig_a_records:
        cp_domains, message = cp_domains_get_domains(dig_ip)
        if args.name not in cp_domains:
            print(
                    f'{txt_time_stamp} '
                    f'[miss_dom] {dig_ip} resolves to {cp_domains}',
                    file=log_file)
        if message:
            print(
                    f'{txt_time_stamp} [cp-d] -ip ------\n{message}',
                    file=log_file_cp_dom)


def monitor_loop(
        log_file: IO[str], log_file_cp_dom: IO[str], args: argparse.Namespace
        ) -> NoReturn:
    """Perform the infinite DNS monitoring loop."""
    last_dig_result = DNSResult()
    last_cp_addresses: set[str] = set()
    dig_ip_mru = LatestUnique()
    while True:
        dig_result = dig_simple(args.name)
        dig_changed = last_dig_result.changed(dig_result)
        txt_time_stamp = dig_result.dig_run.start_time.astimezone().isoformat(
                timespec="seconds")
        if dig_changed:
            print(
                    f'{txt_time_stamp} [dig]      {str_dict(dig_changed)}',
                    file=log_file)
        cp_addresses, message = cp_domains_get_addresses(args.name)
        if message:
            print(
                    f'{txt_time_stamp} [cp-d] -d ------\n{message}',
                    file=log_file_cp_dom)
        if cp_addresses != last_cp_addresses:
            print(f'{txt_time_stamp} [cp-d]     {cp_addresses}', file=log_file)
        dig_a_records = dig_result.get_records('A')
        if dig_a_records:
            check_a_records(
                    dig_a_records, cp_addresses, txt_time_stamp, dig_ip_mru,
                    log_file, log_file_cp_dom, args)
        else:
            print(f'{txt_time_stamp} [dig]      no A records!', file=log_file)
        log_file.flush()
        log_file_cp_dom.flush()
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
    args = parser.parse_args(argv)
    pathlib.Path(DEFAULT_LOG_DIR).mkdir(exist_ok=True)
    log_file_name_params = {
            'date_time': datetime.datetime.now().strftime('%Y%m%d_%H%M')}
    log_file_name = string.Template(DEFAULT_LOG).substitute(log_file_name_params)
    log_file_cp_dom_name = string.Template(
            DEFAULT_LOG_CP_DOMAINS).substitute(log_file_name_params)
    with \
            open(log_file_name, 'a', encoding='utf-8') as log_file, \
            open(log_file_cp_dom_name, 'a', encoding='utf-8') as log_file_cp_dom:
        monitor_loop(log_file, log_file_cp_dom, args)


if __name__ == '__main__':
    main(sys.argv[1:])
