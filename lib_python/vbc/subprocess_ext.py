"""Standard library subprocess extensions.

Requires:
    Python 3.7+

Tested on:
    Check Point Gaia R80.30+
"""

from __future__ import annotations

import contextlib
import datetime
import subprocess
import sys
from typing import IO, Sequence


class AuditedRun(subprocess.CompletedProcess):
    """Perform audited subprocess.run().

    Note: In newer versions of Python inherit from CompletedProcess[str].
    """
    start_time: datetime.datetime
    log_output: bool

    def __init__(
            self, start_time: datetime.datetime | None = None,
            completed_process: subprocess.CompletedProcess
            = subprocess.CompletedProcess((), 0),
            log_output: bool = False) -> None:
        # pylint: disable=W0231  # We do not call super().__init__()
        self.__dict__ = completed_process.__dict__.copy()
        self.start_time = (
            datetime.datetime.now(datetime.timezone.utc) if start_time is None
            else start_time)
        self.log_output = log_output

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
        with contextlib.redirect_stdout(file):
            print(
                f'====== {self.start_time.astimezone().isoformat(timespec="seconds")} '
                f'stat: {self.returncode: 3} args: {self.args}')
            print('------ stdout:')
            print(self.stdout)
            print('------')
            if self.stderr:
                print('------ stderr:')
                print(self.stderr)
                print('------')
            sys.stdout.flush()
