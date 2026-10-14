"""Provide a dbedit provider for the domain model, interacting with the Check Point dbedit tool."""

# cspell:words whereused

from __future__ import annotations

import datetime
import logging
import re
import uuid
from collections.abc import Callable, Generator, Iterable
from typing import Any, ClassVar

from command import get_objects
from cp_model import CPObject, CPObjectProvider, CPObjectReference

_logger = logging.getLogger(__name__)


def _identity_str(value: str) -> str:
    """Return the input string as-is."""
    return value


def _cp_datetime_str(value: str) -> datetime.datetime:
    """Convert a string to a datetime object."""
    return datetime.datetime.strptime(value, "%a %b %d %H:%M:%S %Y").astimezone()


def _dbget_members_str(value: str) -> list[CPObjectReference]:
    """Convert a string to a list of CPObjectReference objects."""
    raise NotImplementedError(
        "Conversion from string to list of CPObjectReference is not implemented yet.")


def _parse_members(text: str) -> Generator[CPObjectReference, None, None]:
    """Parse member objects (group members, references) from a text block."""
    for member_match in re.finditer(
            r"\bName:\s+(?P<name>\S+)(?:\s+\(Table:\s+(?P<table>\S+)\s*\))?", text):
        yield CPObjectReference(
            name=member_match.group("name"), object_table=member_match.group("table"))


def _parse_members_list(text: str) -> list[CPObjectReference]:
    """Parse member objects (group members, references) from a text block and return as a list."""
    return list(_parse_members(text))


class DbeditProvider(CPObjectProvider):
    """Provider for interacting with the Check Point dbedit tool."""

    FIELD_DICTIONARY: ClassVar[dict[str, tuple[str, Callable[[str], Any]]]] = {
        "name": (
            "Object Name", _identity_str),
        "uid": (
            "Object UID", uuid.UUID),
        "object_type": (
            "type", _identity_str),
        "object_table": (
            "Table Name", _identity_str),
        "comments": (
            "Comments", _identity_str),
        "last_modified_by": (
            "Last Modified by", _identity_str),
        "last_modification_time": (
            "Last Modification time", _cp_datetime_str),
        "cdm_auto_calculated": (
            "CDM Auto Calculated", lambda value: value.lower() == "true"),
        # network
        "ipaddr": (
            "ipaddr", _identity_str),
        "netmask": (
            "netmask", _identity_str),
        # group
        "members": (
            "", _parse_members_list),
        # references
        "referrer_objects": (
            # the dependent objects which refers to the object examined by where_used
            # The original dbedit name is confusing.
            "referral_obj", _parse_members_list)
    }
    REFERENCE_FIELDS: ClassVar[tuple[str, ...]] = ("name", "uid", "object_type", "object_table",)
    WHERE_USED_FIELDS: ClassVar[tuple[str, ...]] = ("uid", "referrer_objects",)

    def _model_from_dbedit_dict_single(
            self, dbedit_dict: dict[str, str], model_item_name: str,
            missing_key_log_level: int = logging.WARNING, missing_key_value: Any = None) -> Any:
        """Convert a single dbedit dictionary entry to a model entry."""
        dbedit_item_name, converter = self.FIELD_DICTIONARY[model_item_name]
        try:
            return converter(dbedit_dict[dbedit_item_name])
        except KeyError:
            _logger.log(
                missing_key_log_level,
                "Missing expected key '%s' in dbedit data.", dbedit_item_name)
            return missing_key_value

    def _model_from_dbedit_dict(
            self, dbedit_dict: dict[str, str], model_items: Iterable[str],
            missing_key_log_level: int = logging.WARNING, missing_key_value: Any = None
            ) -> dict[str, Any]:
        """Convert a dbedit dictionary entries to model entries in a dictionary."""
        return {
            model_item_name: self._model_from_dbedit_dict_single(
                dbedit_dict, model_item_name, missing_key_log_level, missing_key_value)
            for model_item_name in model_items
        }

    def get_auto_calculated_objects(self) -> Generator[CPObject, None, None]:
        """Retrieve auto-calculated objects from the database."""
        objects = get_objects("query", "network_objects", "cdm_auto_calculated='true'")
        for obj in objects:
            yield CPObject.from_dbedit_dict(obj)
            # yield CPObject.from_dict(obj)     # TODO

    def get_where_used(self, obj: CPObject) -> Generator[CPObjectReference, None, None]:
        """Retrieve object references for the given object from the database."""
        referrer_objects = get_objects(
            "whereused", obj.object_table, obj.name, skip_preamble=True, parameters_separator="")
        for referrer_object in referrer_objects:
            referrer_object_model = self._model_from_dbedit_dict(
                referrer_object, self.WHERE_USED_FIELDS)
            referrer_objects_inside = referrer_object_model["referrer_objects"]
            if referrer_objects_inside is not None:
                yield from referrer_objects_inside
