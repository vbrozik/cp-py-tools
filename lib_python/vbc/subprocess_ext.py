"""Standard library subprocess extensions.

Requires:
    Python 3.7+

Tested on:
    Check Point Gaia R80.30+
"""

from __future__ import annotations

import contextlib
import datetime
import shlex
import subprocess
import sys
from typing import IO, Iterable, Sequence


def sh_args_quote(args: Iterable[str]) -> str:
    """Convert list of command arguments to an escaped shell command line."""
    return ' '.join(shlex.quote(arg) for arg in args)


class AuditedRun(subprocess.CompletedProcess):
    """Perform audited subprocess.run().

    Note: In newer versions of Python inherit from CompletedProcess[str].
    """
    start_time: datetime.datetime
    log_output: bool
    iterations: int
    """How many times wast the run repeated."""

    def __init__(
            self, start_time: datetime.datetime | None = None,
            completed_process: subprocess.CompletedProcess
            = subprocess.CompletedProcess((), 0),
            log_output: bool = True) -> None:
        # pylint: disable=W0231  # We copy attributes, not call super().__init__()
        self.__dict__ = completed_process.__dict__.copy()
        self.start_time = (
            datetime.datetime.now(datetime.timezone.utc) if start_time is None
            else start_time)
        self.log_output = log_output
        self.iterations = 0

    @classmethod
    def run(
            cls, args: Sequence[str], capture_output: bool = True, check: bool = False,
            encoding: str | None = None) -> AuditedRun:
        """Alternative constructor replacing subprocess.run()."""
        start_time = datetime.datetime.now(tz=datetime.timezone.utc)
        completed_process = subprocess.run(
                args, capture_output=capture_output, check=check, encoding=encoding)
        return cls(start_time, completed_process)

    def log(self, file: IO[str]) -> None:
        """Write result to a log file."""
        if not self.log_output:
            return
        iterations_txt = f'; iter: {self.iterations}' if self.iterations >= 1 else ''
        with contextlib.redirect_stdout(file):
            print(
                f'====== {self.start_time.astimezone().isoformat(timespec="seconds")}  '
                f'stat: {self.returncode: 2}{iterations_txt}\n'
                f'{sh_args_quote(self.args)}')
            print('------ stdout:')
            print(self.stdout.rstrip())
            print('------')
            if self.stderr:
                print('------ stderr:')
                print(self.stderr.rstrip())
                print('------')
            print()
            sys.stdout.flush()
