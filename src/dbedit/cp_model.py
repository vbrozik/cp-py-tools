"""Provide domain model for Check Point management objects.

Requirements:
    - Python 3.7+
"""

# cspell:words cpobj


from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Any, ClassVar
from uuid import UUID

_logger = logging.getLogger(__name__)


class CPObjectProvider(ABC):
    """Abstract base class for CPObject providers."""

    @abstractmethod
    def get_auto_calculated_objects(self) -> Generator[CPObject, None, None]:
        """Retrieve auto-calculated objects from the database."""

    @abstractmethod
    def get_where_used(self, obj: CPObject) -> Generator[CPObjectReference, None, None]:
        """Retrieve object references for the given object from the database."""


def _cpobj_references_to_csv_field(
        references: Iterable[CPObjectReference] | None, separator="|") -> str:
    """Convert an Iterable of CPObjectReference instances to a CSV field string."""
    if not references:
        return ""
    return separator.join(ref.str_short() for ref in references)


def _list_to_csv_field(values: Iterable[Any] | None, separator="|") -> str:
    """Convert an Iterable of strings to a CSV field string."""
    if not values:
        return ""
    return separator.join(str(value) for value in values)


@dataclass
class CPObject:
    """Represents a generic Check Point object."""
    name: str
    uid: UUID
    object_type: str        # TODO: Change to an Enum
    object_table: str
    comments: str
    last_modified_by: str
    last_modification_time: datetime
    cdm_auto_calculated: bool
    where_used: list[CPObjectReference] | None = field(default=None, init=False)

    _registry: ClassVar[dict[str, type[CPObject]]] = {}
    CSV_COLUMN_CONVERTERS: ClassVar[dict[str, Callable[[Any], str]]] = {
        "name": str,
        "uid": str,
        "object_type": str,
        "object_table": str,
        "comments": str,
        "last_modified_by": str,
        "last_modification_time": lambda dt: dt.isoformat(),
        "where_used": _cpobj_references_to_csv_field,
        # TODO: Move to subclasses.
        "ipaddr": str,
        "netmask": str,
        "members": _list_to_csv_field,
    }
    CSV_UTILIZATION_COLUMNS_1: ClassVar[tuple[str, ...]] = (
        "name", "uid", "object_type", "ipaddr", "netmask", "members",
    )
    CSV_UTILIZATION_COLUMNS_2: ClassVar[tuple[str, ...]] = (
        "last_modified_by", "last_modification_time", "where_used",
    )
    CSV_UTILIZATION_COLUMNS: ClassVar[tuple[str, ...]] = (
        CSV_UTILIZATION_COLUMNS_1 + CSV_UTILIZATION_COLUMNS_2)

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        kind = getattr(cls, "kind", None)
        if kind is not None:
            CPObject._registry[kind] = cls

    @classmethod
    def _dbedit_kwargs(cls, data: dict[str, str]) -> dict[str, Any]:
        return {
            "name": data["Object Name"],
            "uid": UUID(data["Object UID"]),
            "object_type": data.get("type", ""),
            "object_table": data.get("Table Name", ""),
            "comments": data.get("comments", ""),
            "last_modified_by": data.get("Last Modified by", ""),
            "last_modification_time": datetime.strptime(
                data["Last Modification time"], "%a %b %d %H:%M:%S %Y"
            ).astimezone(),
            "cdm_auto_calculated": data.get("CDM Auto Calculated", "false").lower() == "true",
        }

    @classmethod
    def from_dbedit_dict(cls, data: dict[str, str]) -> CPObject:
        """Create a CPObject instance from a dictionary."""
        kind = data.get("type", "")
        factory: type[CPObject] = CPObject._registry.get(kind, cls)
        return factory._from_dbedit_dict(data)     # pylint: disable=protected-access
        # We need to use the subclass factory.

    @classmethod
    def _from_dbedit_dict(cls, data: dict[str, str]) -> CPObject:
        args = cls._dbedit_kwargs(data)
        return cls(**args)
        # We use untyped dict. FUTURE: Use TypedDict when dropping 3.7 support.

    def fetch_where_used(self, provider: CPObjectProvider) -> None:
        """Fetch and populate the where_used field using the given provider."""
        if self.where_used is not None:
            _logger.warning(
                "Where used information being fetched repeatedly for object '%s'.", self.name)
        self.where_used = list(provider.get_where_used(self))

    @classmethod
    def get_csv_header(
            cls, columns: Iterable[str] = CSV_UTILIZATION_COLUMNS, separator: str = ",") -> str:
        """Return the CSV header line for the specified columns."""
        return separator.join(columns)

    def to_csv_line(
            self, columns: Iterable[str] = CSV_UTILIZATION_COLUMNS, separator: str = ",") -> str:
        """Convert the CPObject instance to a CSV line using the specified columns."""
        csv_fields: list[str] = []
        for col in columns:
            col_value = getattr(self, col, None)
            # TODO: Replace missing converter by an empty string?
            csv_fields.append(
                self.CSV_COLUMN_CONVERTERS[col](col_value)
                if col_value is not None
                else ""
            )
        return separator.join(csv_fields)


@dataclass
class CPNetworkObject(CPObject):
    """Represents a Check Point network object."""
    kind: ClassVar[str] = "network"
    ipaddr: str
    netmask: str

    @classmethod
    def _dbedit_kwargs(cls, data: dict[str, str]) -> dict[str, Any]:
        return {
            **super()._dbedit_kwargs(data),
            "ipaddr": data["ipaddr"],
            "netmask": data["netmask"],
        }

    @classmethod
    def _from_dbedit_dict(cls, data: dict[str, str]) -> CPNetworkObject:
        args = cls._dbedit_kwargs(data)
        return cls(**args)


@dataclass
class CPGroupObject(CPObject):
    """Represents a Check Point group object."""
    kind: ClassVar[str] = "group"
    members: list[str]

    @staticmethod
    def _parse_members(text: str) -> Generator[str, None, None]:
        for member_match in re.finditer(
                r"\bName:\s+(?P<name>\S+)(?:\s+\(Table:\s+(?P<table>\S+)\s*\))?", text):
            yield member_match.group("name")

    @classmethod
    def _dbedit_kwargs(cls, data: dict[str, str]) -> dict[str, Any]:
        return {
            **super()._dbedit_kwargs(data),
            "members": list(cls._parse_members(data[""])),
        }

    @classmethod
    def _from_dbedit_dict(cls, data: dict[str, str]) -> CPGroupObject:
        args = cls._dbedit_kwargs(data)
        return cls(**args)


def with_comparison_field_cache(cls):
    """Decorator to add a cache of comparison-required field names to a dataclass."""
    cls.COMPARISON_FIELD_NAMES = [
        f.name for f in fields(cls)]
    cls.COMPARISON_NECESSARY_FIELD_NAMES = {
        f.name for f in fields(cls) if f.metadata.get("comparison_necessary")}
    return cls


@with_comparison_field_cache
@dataclass
class CPObjectReference:
    """Represents a reference to a Check Point object.

    Note: Attribute names in this class must match the corresponding attributes in CPObject.
    """
    # Comparison field caches populated by the with_comparison_field_cache decorator.
    COMPARISON_FIELD_NAMES: ClassVar[list[str]]
    COMPARISON_NECESSARY_FIELD_NAMES: ClassVar[set[str]]

    uid: UUID | None = field(default=None, metadata={"comparison_necessary": True})
    name: str | None = field(default=None, metadata={"comparison_necessary": True})
    object_table: str | None = None
    object_type: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CPObjectReference:
        """Create a CPObjectReference instance from a dictionary."""
        if "uid" not in data and "name" not in data:
            _logger.error(
                "Neither 'uid' nor 'name' is present in the data dictionary for CPObjectReference. "
                "Data received: %s", data
                )
        return cls(
            uid=data.get("uid"),
            name=data.get("name"),
            object_table=data.get("object_table"),
            object_type=data.get("object_type"),
        )

    def match_object(self, obj: CPObject) -> bool:
        """Check if this reference matches the given CPObject instance."""
        matched_attributes_necessary = 0
        for attr in self.COMPARISON_FIELD_NAMES:
            self_value = getattr(self, attr)
            obj_value = getattr(obj, attr, None)
            if self_value is not None and obj_value:
                if self_value != obj_value:
                    if (
                            attr not in self.COMPARISON_NECESSARY_FIELD_NAMES
                            and matched_attributes_necessary > 0):
                        _logger.error(
                            "Necessary attributes of object matched but '%s' did not match "
                            "in CPObjectReference.match_object().", attr)
                    return False
                if attr in self.COMPARISON_NECESSARY_FIELD_NAMES:
                    matched_attributes_necessary += 1
        if matched_attributes_necessary <= 0:
            _logger.warning("No necessary attributes matched in CPObjectReference.match_object().")
            return False
        return True

    def str_short(self) -> str:
        """Return a short string representation of the CPObjectReference instance."""
        if self.name is not None:
            return self.name
        elif self.uid is not None:
            return f"{{{self.uid!s}}}"
        else:
            _logger.warning("CPObjectReference instance has neither 'name' nor 'uid'.")
            return "<unnamed_reference>"
