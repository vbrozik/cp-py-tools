"""Tests for the vbc.subprocess_ext module."""

import pytest

from lib_python.vbc.subprocess_ext import sh_args_quote


@pytest.mark.parametrize(
    "args, expected_output",
    [
        pytest.param(
            ["ls", "-la"], "ls -la", id="normal_unix_args"),
        pytest.param(
            ["echo", "Hello, World!"], "echo 'Hello, World!'", id="space_in_arg"),
        pytest.param(
            ["cat", "file with spaces.txt"], "cat 'file with spaces.txt'",
            id="filename_with_spaces"),
        pytest.param(
            ["echo", "$HOME"], "echo '$HOME'", id="arg_with_dollar_sign"),
        pytest.param(
            ["echo", "\"double quotes\""], "echo '\"double quotes\"'", id="arg_with_double_quotes"),
        pytest.param(
            ["echo", "'single quotes'"], "echo '\\'single quotes\\''",
            id="arg_with_single_quotes",
            marks=pytest.mark.xfail(reason="shlex.quote() does not use simple solution")),
        pytest.param(   # Here is the complex solution (create an issue for that?):
            ["echo", "'single quotes'"], """echo ''"'"'single quotes'"'"''""",
            id="arg_with_single_quotes_complex_solution"),
        pytest.param(
            ["echo", "text; rm -rf /"], "echo 'text; rm -rf /'",
            id="arg_with_semicolon_and_dangerous_command"),
        pytest.param(
            [], "", id="empty_args_list"),
    ],
)
def test_sh_args_quote_happy_path(args: list[str], expected_output: str):
    """Test sh_args_quote() with various realistic test values."""
    result = sh_args_quote(args)
    assert result == expected_output


@pytest.mark.parametrize(
    "args, expected_output",
    [
        pytest.param([""], "''", id="single_empty_string_arg"),
        pytest.param([" ", "\t", "\n"], "' ' '\t' '\n'", id="args_with_whitespace_characters"),
        pytest.param(["-n", "-e", "-E"], "-n -e -E", id="args_with_single_dash"),
        pytest.param(["--arg=value"], "--arg=value", id="arg_with_equals_sign"),
        pytest.param(["--", "arg"], "-- arg", id="arg_with_double_dash"),
        pytest.param(["-"], "-", id="single_dash_arg"),
        pytest.param(["\\"], "'\\'", id="single_backslash_arg"),
        pytest.param(["*"], "'*'", id="single_asterisk_arg"),
        pytest.param(["|"], "'|'", id="single_pipe_arg"),
    ],
)
def test_sh_args_quote_edge_cases(args: list[str], expected_output: str):
    """Test sh_args_quote() with various edge cases."""
    result = sh_args_quote(args)
    assert result == expected_output


@pytest.mark.parametrize(
    "args, expected_exception",
    [
        pytest.param(None, TypeError, id="args_is_none"),
        pytest.param(123, TypeError, id="args_is_not_iterable"),
        pytest.param(["arg1", 2, "arg3"], TypeError, id="args_contains_non_string"),
    ],
)
def test_sh_args_quote_error_cases(args: list[str], expected_exception: Exception):
    """Test sh_args_quote() with various error cases."""
    with pytest.raises(expected_exception):     # type: ignore  # Pylance fails to match Exception
        sh_args_quote(args)
