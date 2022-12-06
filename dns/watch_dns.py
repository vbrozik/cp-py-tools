#!/usr/bin/env python3

"""Watch DNS resolution.

Requires:
    Python 3.7+

Tested on:
    Check Point Gaia R80.40+

Usage:
    nohup python3 watch_dns.py watched.url &
"""

from __future__ import annotations

import argparse
import datetime
import re
import string
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, List, Sequence, cast

DEFAULT_INTERVAL = 5
# DEFAULT_LOG_DIR = '/var/log'
DEFAULT_LOG_DIR = '/var/log/watch_dns'
DEFAULT_LOG = DEFAULT_LOG_DIR + '/watch_dns_${date_time}.log'
DEFAULT_LOG_CP_DOMAINS = DEFAULT_LOG_DIR + '/watch_dns_cpdom_${date_time}.log'

CLI_TOOLS_ENCODING = sys.getdefaultencoding()   # probably wrong, TODO test on Windows
NULL_TIME = datetime.datetime(1, 1, 1)


@dataclass(eq=True)
class DNSRecord:
    """Store single DNS resource record (RFC1034) from an answer.

    Fields:
        vvvvvvvvvvvvvv----------------------------- name
                        v-------------------------- ttl
                            vv--------------------- class
                                v------------------ type
                                    vvvvvvvvvvvv--- rdata
        www.seznam.cz.  0   IN  A   77.75.79.222
    """
    name: str
    ttl: int = field(compare=False)
    class_: str
    type_: str
    rdata: str

    def __str__(self) -> str:
        return ' '.join(
                str(item) for item in
                (self.name, self.ttl, self.class_, self.type_, self.rdata))


@dataclass(eq=True)
class DNSResult:
    """Store result of a DNS query using dig."""
    time: datetime.datetime
    status: str = ''
    answers: Sequence[DNSRecord] = ()
    communication_error: str = ''

    def eq_result(self, new: DNSResult) -> bool:
        """Compare two DNSResult objects."""
        return all((
            self.status == new.status,
            self.answers == new.answers,
            self.communication_error == new.communication_error))

    def changed(self, new: DNSResult) -> dict[str, Any]:
        """Get changed fields."""
        result: dict[str, Any] = {}
        if self.status != new.status:
            result['status'] = new.status
        self_answers = (
                self.answers if len(new.answers) == len(self.answers)
                else cast(List[None], [None] * len(new.answers)))
        for index, (self_answer, new_answer) in enumerate(
                                                    zip(self_answers, new.answers)):
            if self_answer != new_answer:
                result[f'answer_{index}'] = new_answer
        if self.communication_error != new.communication_error:
            result['communication_error'] = new.communication_error
        return result

    def get_records(self, record_type: str) -> list[str]:
        """Get values of records of the given type."""
        return [
            record.rdata
            for record in self.answers if record.type_ == record_type]


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
        """Add multiple values."""
        return max(self.add(value) for value in value_list)


def dig_simple(name: str) -> DNSResult:
    """Perform simple DNS query."""
    # time = datetime.datetime.now().astimezone()
    current_time = datetime.datetime.now(datetime.timezone.utc)
    result = subprocess.run(
            ('dig', '+noall', '+answer', '+comments', name),
            capture_output=True, encoding=CLI_TOOLS_ENCODING, check=False)
    response_lines = iter(result.stdout.splitlines())
    first_line = re.sub(r'^;;\s+', '', next(response_lines, ''))
    if first_line.lower() != 'got answer:':
        return DNSResult(
            time=current_time,
            communication_error=(first_line or 'no output from dig'))
    if result.returncode:
        return DNSResult(
            time=current_time,
            communication_error=f'dig returned status code: {result.returncode}')
    status = ''
    answer_section = False
    answers: list[DNSRecord] = []
    for line in response_lines:
        if not status:
            match = re.match(
                    r';;\s+->>HEADER<<-.*\s+status:\s+(?P<status>[a-zA-Z]+)', line)
            if match:
                status = match['status']
                continue
        if re.match(r';;\s+ANSWER\s+SECTION', line):
            answer_section = True
            continue
        if answer_section:
            match = re.match(
                    r'(?P<name>\S+)\s+'
                    r'(?P<ttl>\d+)\s+'
                    r'(?P<class_>\S+)\s+'
                    r'(?P<type_>\S+)\s+'
                    r'(?P<rdata>.+)',
                    line)
            if match:
                answers.append(DNSRecord(**match.groupdict()))
    return DNSResult(time=current_time, status=status, answers=answers)


def cp_domains_parse(command_output: str, header: str) -> tuple[list[str], bool]:
    """Parse output of Check Point domains_tool.

    Todo:
        * Match end of table?
    """
    def is_separator(line: str) -> bool:
        return bool(re.match(r'-{10}', line))

    result: list[str] = []
    output_lines = iter(command_output.splitlines())
    if not is_separator(next(output_lines, '')):
        return result, False
        # raise ValueError("domains_tool output does not start by separator")
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
    log_file_name_params = {
            'date_time': datetime.datetime.now().strftime('%Y%m%d_%H%M')}
    log_file_name = string.Template(DEFAULT_LOG).substitute(log_file_name_params)
    log_file_cp_dom_name = string.Template(
            DEFAULT_LOG_CP_DOMAINS).substitute(log_file_name_params)
    last_dig_result = DNSResult(time=datetime.datetime.now(datetime.timezone.utc))
    last_cp_addresses: set[str] = set()
    dig_ip_mru = LatestUnique()
    with \
            open(log_file_name, 'a', encoding='utf-8') as log_file, \
            open(log_file_cp_dom_name, 'a', encoding='utf-8') as log_file_cp_dom:
        while True:
            dig_result = dig_simple(args.name)
            dig_changed = last_dig_result.changed(dig_result)
            txt_time_stamp = dig_result.time.astimezone().isoformat(timespec="seconds")
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
            log_file.flush()
            log_file_cp_dom.flush()
            last_dig_result = dig_result
            last_cp_addresses = cp_addresses
            time.sleep(args.interval)


if __name__ == '__main__':
    main(sys.argv[1:])
