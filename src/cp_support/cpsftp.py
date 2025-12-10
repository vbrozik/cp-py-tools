#!/usr/bin/env python3

"""SFTP client for exchange of files with Check Point support.

Author:
    Václav Brožík

Requires:
    Python 3.7+

Tested on:
    Check Point Gaia R81.10

Installation:
    mkdir -p /opt/ntt/bin/
    cat > /opt/ntt/bin/cpsftp.py
    # Paste the content of this file and press Ctrl+D
    chmod +x /opt/ntt/bin/cpsftp.py
    ln -s cpsftp.py /opt/ntt/bin/cpsftp
    export PATH=$PATH:/opt/ntt/bin
    # Extend the PATH in .bashrc
    if ! grep -q 'PATH=.*/opt/ntt/bin' ~/.bashrc; then
        echo 'export PATH="$PATH:/opt/ntt/bin/"' >> ~/.bashrc
    fi

Usage:
    cpsftp sr-add           # add SR (support ticket) SFTP account credentials extracted from stdin
    cpsftp sr-select SR_number              # set the current SR SFTP account to the SR_number
    cpsftp sr-list                          # list SR SFTP accounts
    cpsftp get file_name ... [-t path]      # get file_name from the current SR SFTP account
    cpsftp put file_name ... [-t path]      # put file_name to the current SR SFTP account
    cpsftp delete file_name_path            # delete file_name from the current SR SFTP account
    cpsftp ls [path]                        # list files in the current SR SFTP account
    Optional arguments:
        -p proxy_host:proxy_port ...        # use HTTP proxy
"""


from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime
import json
import logging
import operator
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import IO, Any, ClassVar, Dict, Iterable, List, NamedTuple, Sequence, cast


PROG_NAME: str = "cpsftp"
PROG_VERSION: str = "0.1.0.2024091201"

XDG_CONFIG_HOME_VAR: str = "XDG_CONFIG_HOME"
XDG_CONFIG_HOME_DEFAULT: str = "~/.config"
GLOBAL_DIR_PREFIX: str = "/opt/ntt"
GLOBAL_CONFIG_DIR: str = f"{GLOBAL_DIR_PREFIX}/config"
CREATE_GLOBAL_CONFIG: bool = True               # Create global config if no config exists.

CONFIG_FILE: str = f"{PROG_NAME}.json"
JSON_CONFIG_ENCODING: str = "utf-8"

CURL_BINARIES: tuple[str, ...] = ("curl", "curl_cli")
"""Curl binaries to try."""
CURL_TIMEOUT: int = 15
"""Timeout for curl operations in seconds."""

FQDN_PART_RE_STR: str = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
FQDN_RE_STR: str = rf"(?:{FQDN_PART_RE_STR}\.)+{FQDN_PART_RE_STR}"

SR_TEXT_REGEXES: dict[str, re.Pattern[str]] = {
    "account_name": re.compile(
            r"\s*Account\s+Name:\s+(?P<account_name>.+)\s*",
            re.IGNORECASE),
    "account_password": re.compile(
            r"\s*Account\s+Password:\s+(?P<account_password>.+)\s*",
            re.IGNORECASE),
    "sftp_host": re.compile(
            rf".*\s+port\s+22\s+to\s+(?P<sftp_host__1>{FQDN_RE_STR})\s*|"
            rf".*\s+https://(?P<sftp_host__2>{FQDN_RE_STR})/?\s*|"
            rf".*\bsftp\s+(\w+@)?(?P<sftp_host__3>{FQDN_RE_STR})\b.*",
            re.IGNORECASE),
    }
r"""
Regular expressions to parse SR text.

The dict keys are the capture group names. The values are the compiled regexes.

When a regex contains multiple capture groups for the same key, we add a suffix to the key
to distinguish the groups. The suffix is "__\d+". The Python re module does not allow having
multiple capture groups with the same name.

Example SR text:
    SFTP account Credentials:

    Account Name: 6-0003827378
    Account Password: 0r7NGc2jp

    For Web Access, Please go to https://ftp.checkpoint.com

    Please use an SFTP (WinSCP / FileZilla etc..) client on port 22 to ftp.checkpoint.com
"""


class Global:
    """Global variables.

    They include start time and logger.
    """
    current_date_time: ClassVar[datetime.datetime]
    logger: ClassVar[logging.Logger]

    @classmethod
    def initialize(cls, verbosity: int = 0) -> None:
        """Initialize."""
        cls.current_date_time = datetime.datetime.now().astimezone()
        cls.logger = logging.getLogger(PROG_NAME)
        cls.logger.setLevel(cls.log_level_from_verbosity(verbosity))
        handler = logging.StreamHandler()
        handler.setFormatter(
                logging.Formatter(
                        fmt="%(levelname)-8s %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S"))
        cls.logger.addHandler(handler)
        cls.logger.info("Using log level: %s", logging.getLevelName(cls.logger.level))

    @staticmethod
    def log_level_from_verbosity(verbosity: int) -> int:
        """Get log level from verbosity."""
        return max(logging.ERROR - 10 * verbosity, logging.DEBUG)

    @classmethod
    def get_current_date_time(cls) -> datetime.datetime:
        """Get current date time."""
        return cls.current_date_time


def format_not_none(value: Any, format_spec: str = "", none_str = "None") -> str:
    """Format the value or return none_str if the value is None."""
    return none_str if value is None else format(value, format_spec)


class FileListItem(NamedTuple):
    """File list item."""
    name: str
    size: int
    time: datetime.datetime | None = None
    path: str | None = None

    @staticmethod
    def _parse_time(time_str: str) -> datetime.datetime | None:
        """Parse time from the listing.

        Unfortunately the servers use various time formats.
        """
        FORMATS = (
                # 03/01/2024 16:11:19
                "%m/%d/%Y %H:%M:%S",    # USA (most common)
                # 2024-03-01T16:11:19Z
                    "%Y-%m-%dT%H:%M:%SZ",   # ISO 8601 Zulu time (fairfax.ott.checkpoint.com)
        )
        for time_format in FORMATS:
            with contextlib.suppress(ValueError):
                return datetime.datetime.strptime(time_str, time_format)
        Global.logger.warning("Unknown time format: %s", time_str)
        return None

    @classmethod
    def from_cell(cls, cell: Sequence[str]) -> FileListItem:
        """Initialize from cell."""
        return cls(
                name=cell[0],
                size=int(cell[1]),
                time=cls._parse_time(cell[2]),
                path=cell[3] if len(cell) > 3 else None)

    @staticmethod
    def str_tabular_header() -> str:
        """String tabular header."""
        header = ('Date', 'Time', 'Size', 'Name')
        return f"{header[0]:<10} {header[1]:<5} {header[2]:<10} {header[3]}"

    def str_tabular(self) -> str:
        """String tabular representation."""
        return (
                f"{format_not_none(self.time, '%Y-%m-%d %H:%M'):<10} "
                f"{self.size:>10} {self.name}")

    def __str__(self) -> str:
        """String representation."""
        values = [self.name, str(self.size)]
        if self.time is not None:
            values.append(self.time.isoformat())
        return " ".join(values)


@dataclasses.dataclass
class SFTPSessionCurl:
    """SFTP session."""
    login_name: str
    """SFTP login name."""
    login_password: str
    """SFTP login password."""
    sftp_host: str
    """SFTP host."""
    proxy_host: str | None = None
    """Proxy host."""
    proxy_port: int | None = None
    """Proxy port."""
    _curl_bin: str | None = None
    _proxy_args: str | None = None

    @staticmethod
    def _get_curl_bin() -> str | None:
        """Get curl binary."""
        for curl_bin in CURL_BINARIES:
            with contextlib.suppress(FileNotFoundError):
                result = subprocess.run(
                        [curl_bin, "--version"], stdout=subprocess.PIPE, check=True)
                if result.stdout.startswith(b"curl "):
                    return curl_bin
                raise RuntimeError(f"Program {curl_bin} does not behave like curl.")
        return None

    @staticmethod
    def _escape_curl_config_string(value: str) -> str:
        """Escape curl config string.
        
        See https://curl.se/docs/manpage.html#--config
        The string will be enclosed in double quotes (").
        Following characters need to be escaped with backslash:
        \n, \r, \t, \v, \", \\
        """
        escape_map = {
                "\n": r"\n",
                "\r": r"\r",
                "\t": r"\t",
                "\v": r"\v",
                '"': r'\"',
                "\\": r"\\",
                }
        for char, escaped_char in escape_map.items():
            value = value.replace(char, escaped_char)
        return f'"{value}"'

    def _get_curl_config(self) -> list[str]:
        """Get curl config."""
        user_value = self._escape_curl_config_string(
                f"{self.login_name}:{self.login_password}")
        curl_config = [
                "insecure",     # TODO: use proper certificate validation
                "silent",       # suppress progress meter
                "show-error",   # show error messages (normally suppressed by silent)
                f"user = {user_value}",
                ]
        if self._proxy_args is not None:
            curl_config.append(self._proxy_args)
        return curl_config

    def initialize(self) -> None:
        """Initialize the SFTP session."""
        curl_bin = self._get_curl_bin()
        if curl_bin is None:
            raise RuntimeError("curl binary not found")
        self._curl_bin = curl_bin
        if self.proxy_host is not None and self.proxy_port is not None:
            self._proxy_args = (
                    f"proxy = {self.proxy_host}:{self.proxy_port}")

    def _run_curl(self, curl_config: Sequence[str], url: str) -> str:
        """Run curl."""
        if self._curl_bin is None:
            raise RuntimeError("curl binary not found")
        arguments: tuple[str, ...] = (
                    self._curl_bin,
                    "--config", "-",    # read config from stdin
                    "--url", url,
                )
        if Global.logger.isEnabledFor(logging.DEBUG):
            Global.logger.debug("Running curl:")
            Global.logger.debug("  config: %s", curl_config)
            Global.logger.debug("  arguments: %s", arguments)
        result = subprocess.run(
                arguments,
                input="\n".join(curl_config).encode(),
                capture_output=True,
                check=False)
        if Global.logger.isEnabledFor(logging.DEBUG):
            Global.logger.debug("curl result:")
            Global.logger.debug("  returncode: %s", result.returncode)
            Global.logger.debug("  stdout: %s", result.stdout.decode())
            Global.logger.debug("  stderr: %s", result.stderr.decode())
        if result.returncode:
            if result.stderr and re.search(
                    r"Received HTTP code 40[137] from proxy after CONNECT", result.stderr.decode()):
                Global.logger.error("Proxy requires authentication or authorization.")
            raise RuntimeError(f"curl error {result.returncode}: {result.stderr.decode()}")
        if result.stderr:
            raise RuntimeError(f"curl error: {result.stderr.decode()}")
        decoded_output = result.stdout.decode()
        if re.search(
                r"Unauthorized|Forbidden|HTTP/[123.]{1,3}\s401", decoded_output, re.IGNORECASE):
            raise RuntimeError("Authorization failed (bad or expired credentials?)")
        return decoded_output

    def _ls(self, path: str) -> list[dict[str, Any]]:
        """List files returning raw rows."""
        path = path.strip("/")
        curl_config = self._get_curl_config()
        url = f"https://{self.sftp_host}/{path}/?JSON"
        output = self._run_curl(curl_config, url)
        if not output:
            raise RuntimeError(f"curl returned no output for {url}")
        return json.loads(output)["rows"]

    def put(self, local_files: Iterable[str], remote_path: str) -> None:
        """Put files."""
        remote_path = remote_path.strip("/")
        for local_file in local_files:
            curl_config = self._get_curl_config()
            escaped_local_file = self._escape_curl_config_string(local_file)
            curl_config.append(f"upload-file = {escaped_local_file}")
            url = f"https://{self.sftp_host}/{remote_path}/"
            self._run_curl(curl_config, url)

    def get(self, remote_files: Iterable[str], remote_path: str) -> None:
        """Get files."""
        remote_path = remote_path.strip("/")
        for remote_file in remote_files:
            curl_config = self._get_curl_config()
            escaped_file_name = self._escape_curl_config_string(Path(remote_file).name)
            curl_config.append(f"output = {escaped_file_name}")
            current_remote_path = f"/{remote_path}/" if remote_path else "/"
            if remote_file[0] == "/":
                current_remote_path = ""
            url = f"https://{self.sftp_host}{current_remote_path}{remote_file}"
            self._run_curl(curl_config, url)

    def delete(self, remote_file: str) -> None:
        """Delete file."""
        remote_file = remote_file.lstrip("/")
        curl_config = self._get_curl_config()
        curl_config.append("request = DELETE")
        # FIXME: URL encoding of remote_file?
        url = f"https://{self.sftp_host}/{remote_file}"
        self._run_curl(curl_config, url)

    @staticmethod
    def parse_server_date_time(server_date_time: str) -> datetime.datetime:
        """Parse server date time."""
        return datetime.datetime.strptime(server_date_time, "%m/%d/%Y %H:%M:%S")

    def ls(self, path: str) -> list[FileListItem]:
        """List files."""
        return [
                FileListItem.from_cell(row["cell"])
                for row in self._ls(path)]


@dataclasses.dataclass
class SRAccount:
    """Check Point support SR (support request) SFTP account."""
    account_name: str
    account_password: str
    sftp_host: str
    account_birth_time: datetime.datetime = dataclasses.field(
            default_factory=Global.get_current_date_time)
    account_password_birth_time: datetime.datetime = dataclasses.field(
            default_factory=Global.get_current_date_time)
    last_used_time: datetime.datetime = dataclasses.field(
            default_factory=Global.get_current_date_time)
    DATETIME_ATTRIBUTES: ClassVar[set[str]] = {
            "account_birth_time", "account_password_birth_time", "last_used_time"}

    @classmethod
    def _split_datetime_attributes(cls, dict_content: dict[str, Any]) -> dict[str, Any]:
        # sourcery skip: dict-comprehension     # Suggested side effect inside comprehension.
        """Split datetime attributes into separate date and time attributes."""
        date_time_attributes = {}
        for key in cls.DATETIME_ATTRIBUTES:
            if key in dict_content:
                date_time_attributes[key] = dict_content.pop(key)
        return date_time_attributes

    @classmethod
    def from_dict(cls, dict_content: dict[str, str]):
        """Initialize from dict.

        Convert datetime strings to datetime objects.
        """
        dict_content_copy = dict_content.copy()
        date_time_attributes = cls._split_datetime_attributes(dict_content_copy)
        for key, value in date_time_attributes.items():
            if isinstance(value, str):
                date_time_attributes[key] = datetime.datetime.fromisoformat(value)
        return cls(**{**dict_content_copy, **date_time_attributes})

    def to_dict(self) -> dict[str, str]:
        """Convert to dict."""
        dict_content = dataclasses.asdict(self)
        date_time_attributes = self._split_datetime_attributes(dict_content)
        for key, value in date_time_attributes.items():
            if isinstance(value, datetime.datetime):
                date_time_attributes[key] = value.isoformat()
        return {**dict_content, **date_time_attributes}

    @staticmethod
    def _parse_sr_text_line(line: str, account_info: dict[str, str]) -> None:
        """Parse a single SR text line which can contain a single value for account_info.

        account_info is updated with the parsed values.
        """
        def get_key_captured(key: str, match: re.Match[str]) -> str:
            """Return name of captured key or empty string if no key is captured."""
            match_keys = [  # The | operator makes some groups unmatched. We filter them out.
                    match_key for match_key, match_value in match.groupdict().items()
                    if match_value is not None]
            if key in match_keys:
                return key
            for match_key in match_keys:
                if re.fullmatch(rf"{key}__\d+", match_key):
                    return match_key
            return ""

        for key, regex in SR_TEXT_REGEXES.items():
            match = regex.fullmatch(line)
            if match:
                key_captured = get_key_captured(key, match)
                if not key_captured:
                    raise ValueError(f"SR text contains no value for {key}: {match}")
                if (key in account_info and account_info[key] != match[key_captured]):
                    raise ValueError(
                        f"SR text contains multiple different values for {key}: "
                        f"{account_info[key]} and {match[key_captured]}")
                account_info[key] = match[key_captured]
                break
                # We match a single key per line.
                # To check for multiple keys per line, remove the break.

    @classmethod
    def from_sr_text(cls, sr_text: str) -> SRAccount:
        """Initialize from parsed SR text."""
        account_info: dict[str, str] = {}
        for line in sr_text.splitlines():
            cls._parse_sr_text_line(line, account_info)
        if len(account_info) != len(SR_TEXT_REGEXES):
            raise ValueError(
                f"SR text does not contain all required values {tuple(SR_TEXT_REGEXES.keys())}: "
                f"{account_info}")
        return cls(**cast(Dict[str, Any], account_info))    # cast needed for Pylance

    def update(self, other: SRAccount) -> None:
        """Update from other."""
        assert self.account_name == other.account_name, "Update expected for the same account"
        self.account_password = other.account_password
        self.sftp_host = other.sftp_host
        self.account_password_birth_time = other.account_password_birth_time
        self.last_used_time = other.last_used_time

    def list_str(self) -> str:
        """List string."""
        return f"{self.account_name:<14} {self.last_used_time:%Y-%m-%d %H:%M}"

    @classmethod
    def list_str_header(cls) -> str:
        """List string header."""
        return f"{'Account Name':<14} Last Used"


SRAccountListJSON = List[Dict[str, str]]
CPSftpJSON = Dict[str, SRAccountListJSON]

CONFIG_SR_ACCOUNTS_KEY: str = "sr_accounts"
CONFIG_SR_ACCOUNTS_ACCOUNT_NAME_KEY: str = "account_name"


class Config:
    """Configuration file."""
    config_file: Path
    """Configuration file path."""
    config_accounts: dict[str, SRAccount]
    """SR accounts from the configuration file, sorted by last_used_date."""

    def __init__(self, config_file: Path | None = None) -> None:
        """Initialize."""
        if config_file is not None:
            self.config_file = config_file
        else:
            config_file_user = Path(os.path.expanduser(
                    os.environ.get(XDG_CONFIG_HOME_VAR, XDG_CONFIG_HOME_DEFAULT))
                    ) / CONFIG_FILE
            if config_file_user.exists() or not CREATE_GLOBAL_CONFIG:
                self.config_file = config_file_user
            else:
                self.config_file = Path(GLOBAL_CONFIG_DIR) / CONFIG_FILE
        Global.logger.debug("Using config file: %s", self.config_file)
        self.config_accounts = {}

    def _sort_config_accounts(self) -> None:
        """Sort config accounts by last_used_date."""
        self.config_accounts = dict(sorted(
            self.config_accounts.items(),
            key=lambda key_value: key_value[1].last_used_time,
            reverse=True))

    def add_sr_account(self, sr_account: SRAccount) -> None:
        """Add or update SR account."""
        if sr_account.account_name in self.config_accounts:
            self.config_accounts[sr_account.account_name].update(sr_account)
        else:
            self.config_accounts[sr_account.account_name] = sr_account
        self._sort_config_accounts()

    def _initiate_config_file(self) -> None:
        """Initiate config file."""
        Global.logger.debug("Initiating config file: %s", self.config_file)
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, "w", encoding=JSON_CONFIG_ENCODING) as json_file:
            json.dump({CONFIG_SR_ACCOUNTS_KEY: []}, json_file, indent=4)

    def _get_sr_accounts_dict(self) -> SRAccountListJSON:
        """Get SR accounts dict."""
        return [account.to_dict() for account in self.config_accounts.values()]

    def export_sr_accounts(self, stream_handle: IO[str]) -> None:
        """Export SR accounts."""
        json.dump(self._get_sr_accounts_dict(), stream_handle, indent=4)

    def __enter__(self) -> Config:
        """Create empty config file if nonexistent, load it and enter the context."""
        if not self.config_file.exists():
            self._initiate_config_file()
        with open(self.config_file, encoding=JSON_CONFIG_ENCODING) as json_file:
            config_content_raw: CPSftpJSON = json.load(json_file)
        sr_accounts: SRAccountListJSON = config_content_raw.get(CONFIG_SR_ACCOUNTS_KEY, [])
        if not isinstance(sr_accounts, list):
            raise ValueError(
                f"{CONFIG_SR_ACCOUNTS_KEY} from {self.config_file} is not a list")
        self.config_accounts = {
                item[CONFIG_SR_ACCOUNTS_ACCOUNT_NAME_KEY]: SRAccount.from_dict(item)
                for item in sr_accounts}
        self._sort_config_accounts()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        del exc_type, exc_value, traceback
        self._sort_config_accounts()
        config_content_raw: CPSftpJSON = {CONFIG_SR_ACCOUNTS_KEY: self._get_sr_accounts_dict()}
        with open(self.config_file, "w", encoding=JSON_CONFIG_ENCODING) as json_file:
            json.dump(config_content_raw, json_file, indent=4)

    def debug_print(self) -> None:
        """Debug print."""
        print(f"Config file: {self.config_file}")
        print("Config accounts:")
        for account in self.config_accounts.values():
            print(account)

    def list_sr_accounts(self) -> None:
        """List SR accounts."""
        print(SRAccount.list_str_header())
        for account in self.config_accounts.values():
            print(account.list_str())

    def select_sr_account(self, account_name: str) -> None:
        """Select SR account."""
        if account_name not in self.config_accounts:
            raise ValueError(f"SR account {account_name} not found")
        self.config_accounts[account_name].last_used_time = Global.get_current_date_time()
        self._sort_config_accounts()

    def get_active_sr_account(self) -> SRAccount:
        """Get active SR account."""
        return next(iter(self.config_accounts.values()))


def parse_cli_args(args: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description='SFTP client for Check Point support.')

    parser.add_argument(
        "--proxy", "-p", help="Use HTTP proxy host:port", metavar="host:port")
    parser.add_argument(
        "--verbosity", "-v", help="Verbosity level", type=int, default=0)

    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    subparsers.add_parser("version", help="Show version")

    subparsers.add_parser("sr-add", help="Add SR SFTP account")

    subparsers.add_parser("sr-list", help="List SR SFTP accounts")

    subparsers.add_parser("sr-export", help="Export SR SFTP accounts")

    subparsers.add_parser("sr-config", help="Show SR SFTP account configuration file path")

    subparser_sr_select = subparsers.add_parser("sr-select", help="Select SR SFTP account")
    subparser_sr_select.add_argument("account_name", help="SR SFTP account name (SR number)")

    subparser_ls = subparsers.add_parser("ls", help="List files in the current SR SFTP account")
    subparser_ls.add_argument("path", help="Path to list", nargs="?", default="/")
    subparser_ls.add_argument("--sort", help="Sort by", choices=["time"])

    subparser_put = subparsers.add_parser("put", help="Put files to the current SR SFTP account")
    subparser_put.add_argument("file_names", help="File names to upload", nargs="+")
    subparser_put.add_argument(
            "--target", "-t", help="Path to put file into", default="incoming/")

    subparser_get = subparsers.add_parser("get", help="Get files from the current SR SFTP account")
    subparser_get.add_argument("file_names", help="File names to download", nargs="+")
    subparser_get.add_argument(
            "--source", "-s", help="Path to get file from", default="outgoing/")

    subparser_delete = subparsers.add_parser(
            "delete", help="Delete file from the current SR SFTP account")
    subparser_delete.add_argument("file_path", help="Path of file to delete")

    return parser.parse_args(args)


def get_gaia_http_proxy() -> tuple[str, int]:
    """Get HTTP proxy configuration from Gaia, return host and port."""
    proxy_host = subprocess.run(
            ["dbget", "proxy:ip-address"], capture_output=True, check=True, text=True
            ).stdout.strip()
    proxy_port = int(subprocess.run(
            ["dbget", "proxy:port"], capture_output=True, check=True, text=True
            ).stdout.strip())
    return proxy_host, proxy_port


def is_gaia() -> bool:
    """Check if the script is running on Gaia."""
    return Path("/etc/cp-release").exists()


def sftp_commands(parsed_args: argparse.Namespace, config: Config) -> None:
    """SFTP commands."""
    sftp_account = config.get_active_sr_account()
    Global.logger.info("Using SFTP account: %s", sftp_account.account_name)
    sftp_additional_arguments: dict[str, Any] = {}
    if parsed_args.proxy:
        proxy_host, proxy_port = parsed_args.proxy.split(":")
        sftp_additional_arguments.update(proxy_host=proxy_host, proxy_port=int(proxy_port))
    elif parsed_args.proxy != "" and is_gaia():
        gaia_proxy_host, gaia_proxy_port = get_gaia_http_proxy()
        sftp_additional_arguments.update(proxy_host=gaia_proxy_host, proxy_port=gaia_proxy_port)
    curl_session = SFTPSessionCurl(
            login_name=sftp_account.account_name,
            login_password=sftp_account.account_password,
            sftp_host=sftp_account.sftp_host,
            **sftp_additional_arguments)
    curl_session.initialize()
    if parsed_args.command == "ls":
        Global.logger.info("Listing files in %s:", parsed_args.path)

        def ls_sort_key(file_list_item: FileListItem) -> Any:
            del file_list_item
            return 0
        if parsed_args.sort == "time":
            # flake8: noqa  # redefinition of unused 'ls_sort_key' ; Flake8(F811)
            ls_sort_key = operator.attrgetter("time")  # type: ignore  # pylance
        print(FileListItem.str_tabular_header())
        for file_item in sorted(curl_session.ls(parsed_args.path), key=ls_sort_key):
            print(file_item.str_tabular())
    elif parsed_args.command == "put":
        print(f"Putting {parsed_args.file_names} to {parsed_args.target}:")
        curl_session.put(parsed_args.file_names, parsed_args.target)
    elif parsed_args.command == "get":
        print(f"Getting {parsed_args.file_names} from {parsed_args.source}:")
        curl_session.get(parsed_args.file_names, parsed_args.source)
    elif parsed_args.command == "delete":
        print(f"Deleting {parsed_args.file_path}:")
        curl_session.delete(parsed_args.file_path)
    else:
        raise ValueError(f"Unknown command: {parsed_args.command}")


def main(args: Sequence[str] | None = None):
    """Main function."""
    parsed_args = parse_cli_args(args)
    Global.initialize(verbosity=parsed_args.verbosity)
    with Config() as config:
        if parsed_args.command == "version":
            print(f"{PROG_NAME} version {PROG_VERSION}")
        elif parsed_args.command == "sr-add":
            print("\nPaste the text from the ticket with account credentials and press Ctrl+D:")
            config.add_sr_account(SRAccount.from_sr_text(sys.stdin.read()))
        elif parsed_args.command == "sr-list":
            config.list_sr_accounts()
        elif parsed_args.command == "sr-export":
            config.export_sr_accounts(sys.stdout)
        elif parsed_args.command == "sr-config":
            print(config.config_file)
        elif parsed_args.command == "sr-select":
            config.select_sr_account(parsed_args.account_name)
            print(f"selected SFTP account: {parsed_args.account_name}")
        else:
            sftp_commands(parsed_args, config)


if __name__ == '__main__':
    main(args=sys.argv[1:])
