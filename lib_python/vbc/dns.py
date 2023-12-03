"""Functions and classes for DNS resolution using dig.

Requires:
    Python 3.7+

Tested on:
    Check Point Gaia R80.30+
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import Any, List, Sequence, cast

from vbc.subprocess_ext import AuditedRun


CLI_TOOLS_ENCODING = sys.getdefaultencoding()   # probably wrong, TODO test on Windows


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
    ttl: str = field(compare=False)
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
    dig_run: AuditedRun = field(default_factory=AuditedRun)
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


def dig_simple(name: str) -> DNSResult:
    """Perform simple DNS query using dig."""
    run_result = AuditedRun.run(
            ('dig', '+noall', '+answer', '+comments', name),
            capture_output=True, encoding=CLI_TOOLS_ENCODING, check=False)
    response_lines = iter(run_result.stdout.splitlines())
    first_line = re.sub(r'^;;\s+', '', next(response_lines, ''))
    if first_line.lower() != 'got answer:':
        return DNSResult(
            dig_run=run_result,
            communication_error=(first_line or 'no output from dig'))
    if run_result.returncode:
        return DNSResult(
            dig_run=run_result,
            communication_error=f'dig returned status code: {run_result.returncode}')
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
    return DNSResult(
            dig_run=run_result, status=status, answers=answers)
