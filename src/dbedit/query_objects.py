"""Query objects from the Check Point database using dbedit.

Requirements:
    - Python 3.7+
    - Check Point dbedit tool available in the system PATH.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Generator, Iterable, Sequence
from enum import Enum

from command import get_objects
from cp_model import CPObject
from dbedit_provider import DbeditProvider

_logger = logging.getLogger(__name__)


class OutputFormat(Enum):
    """Output format for the query_objects script."""
    CSV = "csv"
    TSV = "tsv"
    JSON = "json"
    OBJECTS = "objects"


def parse_cli_args(argv: list[str]) -> argparse.Namespace:
    """Parse command line arguments for the query_objects script.

    Args:
        argv: List of command line arguments.

    Returns:
        An argparse.Namespace object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Query objects from the Check Point database using dbedit.")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument(
        "-Q", "--query-template", help="Specify the query template to use.",
        nargs=1, type=str, choices=("auto_calculated",))
    parser.add_argument(
        "-F", "--output-format", help="Specify the output format.",
        nargs=1, type=str, choices=[member.value for member in OutputFormat],
        default=[OutputFormat.CSV.value],
        )
    return parser.parse_args(argv)


def query_objects(query_template: str) -> Generator[dict[str, str], None, None]:
    """Query objects from the Check Point database using the specified query template.

    Args:
        query_template: The query template to use.

    Returns:
        A generator yielding dictionaries representing the retrieved objects.
    """
    if query_template == "auto_calculated":
        result = get_objects("query", "network_objects", "cdm_auto_calculated='true'")
    else:
        raise ValueError(f"Unsupported query template: {query_template}")
    yield from result


def object_dict_to_csv(obj: dict[str, str], columns: Iterable[str]) -> str:
    """Convert an object dictionary to a CSV line containing only the specified columns.

    Args:
        obj: The object dictionary to convert.
        columns: The columns to include in the CSV line.

    Returns:
        A CSV line as a string.
    """
    return ",".join(str(obj.get(col, "")) for col in columns)


def objects_to_csv(
        objects: Iterable[dict[str, str]], columns: Sequence[str], line_terminator: str = "\n",
        write_header: bool = True,
        ) -> Generator[str, None, None]:
    """Convert an iterable of object dictionaries to CSV lines containing the specified columns.

    Args:
        objects: The iterable of object dictionaries to convert.
        columns: The columns to include in the CSV string.

    Returns:
        A generator yielding CSV lines for each object.
    """
    if write_header:
        yield ",".join(columns) + line_terminator
    for obj in objects:
        yield object_dict_to_csv(obj, columns) + line_terminator


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for query_objects.

    Args:
        argv: Optional list of command line arguments (for testing). If None, uses sys.argv.

    Returns:
        An integer exit code (0 for success, 1 for failure).
    """
    args = parse_cli_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    if args.query_template:
        query_template = args.query_template[0]
        output_format = OutputFormat(args.output_format[0])
        objects = query_objects(query_template)
        dbedit_provider = DbeditProvider()

        # if output_format == OutputFormat.CSV:
        #     COLUMNS = (
        #         "Object Name", "Object UID", "type", "Last Modified by", "Last Modification time",
        #         "ipaddr", "netmask")
        #     sys.stdout.writelines(objects_to_csv(objects, COLUMNS))
        if output_format == OutputFormat.JSON:
            json.dump(
                list(objects),
                sys.stdout, indent=4,
                # iterable_as_array=True,   # FUTURE: Since Python 3.8
                )
        elif output_format in {OutputFormat.OBJECTS, OutputFormat.TSV, OutputFormat.CSV}:
            # cp_objects = []
            csv_type_format = output_format in {OutputFormat.TSV, OutputFormat.CSV}
            separator = "\t" if output_format == OutputFormat.TSV else ","
            if csv_type_format:
                print(CPObject.get_csv_header(separator=separator))
            for obj in objects:
                cp_obj = CPObject.from_dbedit_dict(obj)
                cp_obj.fetch_where_used(dbedit_provider)
                if csv_type_format:
                    print(cp_obj.to_csv_line(separator=separator))
                else:
                    print(cp_obj)
                # cp_objects.append(cp_obj)
        else:
            _logger.error("Unsupported output format: %s", output_format)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
