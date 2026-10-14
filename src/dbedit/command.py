"""Provide Python wrappers for Check Point dbedit.

Dbedit is the pre-R80 management server object database tool.

Minimum Python version: 3.7
"""

from __future__ import annotations

import contextlib
import logging
import pathlib
import re
import subprocess
import tempfile
import threading
from collections.abc import Generator, Iterable
from typing import TextIO

SMALL_TMP_DIR: str = "/dev/shm"
"""Directory for small temporary files."""

_logger = logging.getLogger(__name__)
"""Logger for the module."""


def _drain_stream_prefix(
        stream: TextIO, prefix_parts: list[str],
        max_bytes: int = 4096, block_bytes: int = 1024) -> None:
    """Drain a stream, capture its start, and discard the rest.

    Normally this function would be run asynchronously in a separate thread to avoid blocking.

    Args:
        stream: The text stream to read from.
        prefix_parts: A list to which the captured prefix parts will be appended.
        max_bytes: The maximum number of bytes to capture from the stream.
        block_bytes: The number of bytes to read in each block.
    """
    collected = 0
    while True:
        try:
            chunk = stream.read(block_bytes)
        except ValueError as exception:
            _logger.warning("Error reading from stream: %s", exception)
            break
        if not chunk:   # End of stream reached
            break
        if collected < max_bytes:
            remaining = max_bytes - collected
            prefix_parts.append(chunk[:remaining])
            collected += min(len(chunk), remaining)


@contextlib.contextmanager
def _small_tmp_file(content: str) -> Generator[str]:
    """Provide a small temporary file with the given content as a context manager.

    This context manager ensures that the temporary file is properly cleaned up after use.

    Args:
        content: The content to write to the temporary file.

    Returns:
        The path to the created temporary file.
    """
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=SMALL_TMP_DIR) as tmp_file:
        tmp_file.write(content)
        # tmp_file.flush()        # Flush the user-space buffer to the kernel buffer.
        tmp_file.file.close()   # Close the underlying file to flush it to disk.
        yield tmp_file.name


def get_objects_from_lines(
        lines: Iterable[str], skip_preamble: bool = True) -> Generator[dict[str, str]]:
    """Parse objects from lines of dbedit output.

    Objects are separated by an empty line.

    Example structure of dbedit output lines:
        Object Name: MyNetworkObject
        Object UID: {012...}
        Fields details
        --------------
            NAT: (
                <NULL>
            )
            comments: This is a comment.
            ipaddr: 192.168.1.1

    Args:
        lines: An iterable of lines from dbedit output.

    Returns:
        A generator of dictionaries representing the parsed objects.
    """
    current_object: dict[str, str] = {}
    in_multiline_field: str | None = None   # the key of the current multiline field, if any
    object_count: int = 0                   # the number of objects parsed so far
    object_count_from_preamble: int = -1    # the number of objects reported in the preamble, if any
    for line in lines:
        line = line.strip()
        key_value_match = re.match(r"^(?P<key>[\w\s]+\w+|)\s*:\s*(?P<value>.*)$", line)
        object_count_match = re.match(r"^Num(?:eb|be)r of results:\s*(?P<count>\d+$)", line)
        # FUTURE: When removing Python 3.7 support, change to the walrus operator.
        if not line:
            if in_multiline_field is not None:
                _logger.warning("Empty line in multiline field for field: %s", in_multiline_field)
            elif current_object:
                yield current_object
                current_object = {}
                object_count += 1
        elif in_multiline_field is not None:
            in_multiline_field_last = in_multiline_field
            if line.endswith(")"):
                in_multiline_field = None
                line = line[:-1].strip()
            current_object[in_multiline_field_last] += line + "\n"
        elif re.match(r"(?i)^\s*(?:fields\s+details|-{3,})\s*$", line):
            continue
        elif skip_preamble and not current_object and object_count_match:
            object_count_from_preamble = int(object_count_match.group("count"))
            continue
        elif key_value_match:
            key = key_value_match.group("key")
            value = key_value_match.group("value")
            if value.startswith("("):
                in_multiline_field = key
                value = value[1:].strip() + "\n"
            current_object[key] = value
        else:
            _logger.warning("Unrecognized line format: %s", line)
    if current_object:
        yield current_object
        object_count += 1
    _logger.debug("Total objects parsed: %d", object_count)
    if object_count_from_preamble >= 0 and object_count_from_preamble != object_count:
        _logger.warning(
            "Mismatch between object count from preamble (%d) and actual parsed count (%d)",
            object_count_from_preamble, object_count)


def get_objects(
        command: str, table: str, parameters: str, skip_preamble: bool = True,
        parameters_separator: str = ",",
        ) -> Generator[dict[str, str]]:
    """Retrieve objects from the database using the specified command.

    Example:
        get_objects("query", "network_objects", "cdm_auto_calculated='true'")

    Args:
        command: The dbedit command to execute.
        table: The table from which to retrieve objects (e.g., "network_objects").
        parameters: Additional parameters to pass to the dbedit command.

    Returns:
        A list of dictionaries representing the retrieved objects.

    Todo:
        - Decide best parameter for `parameters_separator` and the default value.
    """
    separated_parameters = f"{parameters_separator} {parameters}" if parameters else ""
    # FUTURE: When removing Python 3.9 support, use round brackets in the multiline with statement.
    command_args = ["dbedit", "-local", "-f",]
    with \
            _small_tmp_file(
                content=f"{command} {table}{separated_parameters}\nquit\n") as command_file, \
            subprocess.Popen(
                args=command_args + [command_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        if process.stdout is None:
            raise RuntimeError("Failed to get objects using dbedit.")
        command_args = command_args + [command_file]

        # Asynchronously drain stderr to capture error messages without blocking the main thread.
        stderr_parts: list[str] = []
        stderr_thread = threading.Thread(
            target=_drain_stream_prefix, args=(process.stderr, stderr_parts), daemon=True)
        stderr_thread.start()

        # Parse the output from dbedit.
        yield from get_objects_from_lines(process.stdout, skip_preamble=skip_preamble)

        # Wait for the stderr thread to finish to ensure all error messages are captured.
        stderr_thread.join()

        # Check for errors in stderr.
        if stderr_parts:
            _logger.warning(
                "Error messages showed up while executing dbedit command: %s",
                "".join(stderr_parts))
        process.wait()
        if process.returncode != 0:
            # with open(command_file, "r", encoding="utf-8") as command_file_handle:
            #     command_file_content = command_file_handle.read()
            _logger.warning(
                "dbedit command %s exited with non-zero return code: %s; stderr: %s; file: %s",
                command_args, process.returncode, "".join(stderr_parts),
                pathlib.Path(command_file).read_text(encoding="utf-8"))
