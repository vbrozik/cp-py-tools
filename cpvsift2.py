#!/usr/bin/env python3

"""Test Check Point VSX cluster connectivity over all interfaces.

Version 2
Requirements: Python 3.8+
"""

from __future__ import annotations

import argparse
import contextlib


def main():
    """Provide CLI interface."""
    # --- CLI interface
    print(
        'Use this script on every VSX to collect interfaces to a file:\n'
        r"""printf "cat >%s << '+++EOF'\n" """
        r'''"$(date -I)_$(hostname)_interfaces.txt" &&''' '\n'
        r"""ip -all netns exec ip -4 -o addr ; printf '+++EOF\n'"""
        '\n')
    parser = argparse.ArgumentParser()
    parser.add_argument(
            'in_files', nargs='+', type=argparse.FileType('r'),
            help="input files containing listing of interfaces from "
            "individual VSX")
    args = parser.parse_args()
    # --- file input
    with contextlib.ExitStack() as in_file_stack:
        in_files = [
                    in_file_stack.enter_context(in_file)
                    for in_file in args.in_files]
        print('\n'.join(in_file.name for in_file in in_files))
    # --- processing and output


if __name__ == '__main__':
    main()
