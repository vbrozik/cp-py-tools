#!/usr/bin/env python3

"""Analyze data from Check Point spike detective."""

from abc import ABC, abstractmethod
import argparse
import bisect
from collections import Counter, defaultdict
import contextlib
import copy
import datetime
import enum
import functools
from pathlib import Path
import re
from dataclasses import dataclass, field
import sys
from typing import ClassVar, Sequence


LOCAL_TIME_ZONE = datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo
"""Local time zone."""
assert LOCAL_TIME_ZONE is not None, "Failed to get local time zone."


LOG_REGEX = re.compile(r"""
    \s*
    (?P<record_time>\w{2,10}\ \d{1,2}\ \d{1,2}:\d{2}:\d{2}\ \d{4})\s+
    (?P<origin>\S+)\s+
    spike_detective:\s+spike\s+info:\s+
    type:\s+(?P<spike_type>\w+),\s+
    (?: # CPU spike specific fields:
        cpu\s+core:\s+(?P<cpu_core>\d+),\s+
        top\s+consumer:\s+(?P<top_consumer>[^,]+),\s+
    )?
    (?: # Thread spike specific fields:
        thread\s+id:\s+(?P<thread_id>\d+),\s+
        thread\s+name:\s+(?P<thread_name>[^,]+),\s+
    )?
    start\s+time:\s+(?P<start_time>\d{1,2}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}),\s+
    spike\s+duration\s+\(sec\):\s+(?P<duration>\d+),\s+
    initial\s+cpu\s+usage:\s+(?P<initial_cpu_usage>\d+),\s+
    average\s+cpu\s+usage:\s+(?P<average_cpu_usage>\d+),\s+
    perf\s+taken:\s+(?P<perf_taken>\d+)\s*
    """, re.VERBOSE)


class SpikeType(enum.Enum):
    """Spike type enum."""
    CPU = "cpu"
    THREAD = "thread"

    @classmethod
    def from_str(cls, value: str) -> "SpikeType":
        """Return a SpikeType from a string."""
        for spike_type in SpikeType:
            if spike_type.value == value:
                return spike_type
        raise ValueError("Unknown spike type.")


# pylint: disable=too-many-instance-attributes      # Attributes of a log record.
@dataclass(frozen=True)
class SpikeInfo(ABC):
    """Information about a spike - common part."""
    record_time: datetime.datetime
    """Time the log was recorded."""
    origin: str
    """Origin of the log - hostname of the firewall."""
    spike_type: SpikeType
    """Type of the spike - either spike of a CPU or thread."""
    start_time: datetime.datetime
    """Time the spike started."""
    end_time: datetime.datetime
    """Time the spike ended."""
    duration: int
    """Duration of the spike in seconds."""
    initial_cpu_usage: int
    """Initial CPU usage when the spike started."""
    average_cpu_usage: int
    """Average CPU usage during the spike."""
    perf_taken: bool
    """Whether output of perf was taken during the spike."""
    original_log: str
    """Original log line."""
    time_zone: ClassVar[datetime.tzinfo] = LOCAL_TIME_ZONE

    @staticmethod
    def log_line_is_spike(log_line: str) -> bool:
        """Return whether a log line is a spike."""
        return " spike_detective: " in log_line

    @classmethod
    def from_log(cls, log_line: str) -> "SpikeInfo":
        """Create a SpikeInfo object from a log line."""
        match = LOG_REGEX.match(log_line)
        if not match:
            raise ValueError("Log line does not match the expected format.")
        data = match.groupdict()
        attributes = {
                "record_time": datetime.datetime.strptime(
                        data["record_time"], "%b %d %H:%M:%S %Y").replace(tzinfo=cls.time_zone),
                "origin": data["origin"],
                "spike_type": SpikeType.from_str(data["spike_type"]),
                "start_time": datetime.datetime.strptime(
                        data["start_time"], "%d/%m/%y %H:%M:%S").replace(tzinfo=cls.time_zone),
                "duration": int(data["duration"]),
                "initial_cpu_usage": int(data["initial_cpu_usage"]),
                "average_cpu_usage": int(data["average_cpu_usage"]),
                "perf_taken": bool(int(data["perf_taken"])),
                "original_log": log_line,
                }
        attributes["end_time"] = attributes["start_time"] + datetime.timedelta(
                seconds=attributes["duration"])
        if attributes["spike_type"] == SpikeType.CPU:
            attributes["cpu_core"] = int(data["cpu_core"])
            attributes["top_consumer"] = data["top_consumer"]
            return CPUSpikeInfo(**attributes)
        elif attributes["spike_type"] == SpikeType.THREAD:
            attributes["thread_id"] = int(data["thread_id"])
            attributes["thread_name"] = data["thread_name"]
            return ThreadSpikeInfo(**attributes)
        raise ValueError("Unknown spike type.")

    @abstractmethod
    def get_sub_type_str(self) -> str:
        """Return a string with the sub-type of the spike."""
        pass

    def get_cpu_seconds(self) -> float:
        """Return CPU seconds used by the spike."""
        return self.duration * self.average_cpu_usage / 100


@dataclass(frozen=True)
class CPUSpikeInfo(SpikeInfo):
    """Information about a CPU spike."""
    cpu_core: int
    """CPU core number that spiked if the type is CPU."""
    top_consumer: str
    """Top consumer that spiked if the type is CPU."""

    def get_sub_type_str(self) -> str:
        """Return a string with the sub-type of the spike."""
        return f"{self.cpu_core:2d}"


@dataclass(frozen=True)
class ThreadSpikeInfo(SpikeInfo):
    """Information about a thread spike."""
    thread_id: int
    """Thread ID that spiked if the type is thread."""
    thread_name: str
    """Thread name that spiked if the type is thread."""

    def get_sub_type_str(self) -> str:
        """Return a string with the sub-type of the spike."""
        return f"{self.thread_name}"


@functools.total_ordering
@dataclass
class SpikeChangeEvent:
    """Event when spikes change their state (a spike starts or ends)."""
    time: datetime.datetime
    """Time of the event."""
    spikes_started: set[SpikeInfo]
    """List of spikes that started at the time of the event."""
    spikes_ended: set[SpikeInfo]
    """List of spikes that ended at the time of the event."""
    spikes_active: set[SpikeInfo]
    """List of spikes that were active at least from the time of the event till the next event."""

    def __lt__(self, other: "SpikeChangeEvent") -> bool:
        """Return whether the event is earlier than another event."""
        return self.time < other.time

    def __eq__(self, other: "SpikeChangeEvent") -> bool:
        """Return whether the event is later than another event."""
        return self.time == other.time

    def __copy__(self) -> "SpikeChangeEvent":
        """Return a copy of the event.

        Sets are copied so that they can be modified independently.
        """
        return SpikeChangeEvent(
                self.time, self.spikes_started.copy(), self.spikes_ended.copy(),
                self.spikes_active.copy())

    @staticmethod
    def _do_spike_and_event_types_match(spike: SpikeInfo, event: "SpikeChangeEvent") -> bool:
        """Provide spike and event type match for assertions."""
        return (
            (isinstance(spike, CPUSpikeInfo) == isinstance(event, CPUSpikeChangeEvent)) and
            (isinstance(spike, ThreadSpikeInfo) == isinstance(event, ThreadSpikeChangeEvent)) and
            (isinstance(spike, CPUSpikeInfo) != isinstance(spike, ThreadSpikeInfo)))

    def clone(self, new_time: datetime.datetime) -> "SpikeChangeEvent":
        """Return a copy of the event with a new time and start/stop events cleared."""
        new_event = copy.copy(self)
        new_event.time = new_time
        new_event.spikes_started = set()
        new_event.spikes_ended = set()
        return new_event

    @classmethod
    def from_spike_start(
            cls, spike: SpikeInfo, previous_event: "SpikeChangeEvent | None" = None
            ) -> "SpikeChangeEvent":
        """Create a SpikeChangeEvent object from a spike start."""
        if previous_event is None:
            if isinstance(spike, CPUSpikeInfo):
                new_event = CPUSpikeChangeEvent(
                        spike.start_time, {spike}, set(), {spike}, {spike.cpu_core},
                        spike.average_cpu_usage)
            elif isinstance(spike, ThreadSpikeInfo):
                new_event = ThreadSpikeChangeEvent(
                        spike.start_time, {spike}, set(), {spike}, {spike.thread_id},
                        spike.average_cpu_usage)
            else:
                assert False, "Unknown spike type."
        else:
            assert cls._do_spike_and_event_types_match(
                    spike, previous_event), "Spike and event types do not match."
            new_event = previous_event.clone(spike.start_time)
            new_event.add_start_event(spike)
        return new_event

    @classmethod
    def from_spike_end(
            cls, spike: SpikeInfo, previous_event: "SpikeChangeEvent") -> "SpikeChangeEvent":
        """Create a SpikeChangeEvent object from a spike end."""
        assert cls._do_spike_and_event_types_match(spike, previous_event), (
                f"Spike and event types do not match: {type(spike)}, {type(previous_event)}")
        new_event = previous_event.clone(spike.end_time)
        new_event.add_end_event(spike)
        return new_event

    def add_active_spike(self, spike: SpikeInfo) -> None:
        """Add an active spike to the list."""
        self.spikes_active.add(spike)

    def remove_active_spike(self, spike: SpikeInfo) -> None:
        """Remove an active spike from the list."""
        self.spikes_active.remove(spike)

    def add_start_event(self, spike: SpikeInfo) -> None:
        """Add a start event to the list."""
        self.spikes_started.add(spike)
        self.add_active_spike(spike)

    def add_end_event(self, spike: SpikeInfo, remove_active_spike: bool = False) -> None:
        """Add an spike end event to the event."""
        self.spikes_ended.add(spike)
        if remove_active_spike:         # Note: Probably not needed.
            self.remove_active_spike(spike)


@dataclass
class CPUSpikeChangeEvent(SpikeChangeEvent):
    """Event when CPU spikes change their state (a spike starts or ends)."""
    cpus_spiked: set[int]
    """List of CPU cores that spiked at the time of the event."""
    cpu_usage: int
    """CPU usage at the time of the event as a sum of average CPU usages."""

    def add_active_spike(self, spike: CPUSpikeInfo) -> None:
        """Add active spike."""
        self.cpus_spiked.add(spike.cpu_core)
        self.cpu_usage += spike.average_cpu_usage
        return super().add_active_spike(spike)

    def remove_active_spike(self, spike: CPUSpikeInfo) -> None:
        """Remove active spike."""
        self.cpus_spiked.remove(spike.cpu_core)
        self.cpu_usage -= spike.average_cpu_usage
        return super().remove_active_spike(spike)

    def __copy__(self) -> "CPUSpikeChangeEvent":
        # Note: Is there a way to use super() here?
        return CPUSpikeChangeEvent(
                self.time, self.spikes_started.copy(), self.spikes_ended.copy(),
                self.spikes_active.copy(), self.cpus_spiked.copy(), self.cpu_usage)


@dataclass
class ThreadSpikeChangeEvent(SpikeChangeEvent):
    """Event when thread spikes change their state (a spike starts or ends)."""
    threads_spiked: set[int]
    """List of thread IDs that spiked at the time of the event."""
    thread_cpu_usage: int
    """CPU usage at the time of the event as a sum of average CPU usages of threads."""

    def add_active_spike(self, spike: ThreadSpikeInfo) -> None:
        """Add active spike."""
        self.threads_spiked.add(spike.thread_id)
        self.thread_cpu_usage += spike.average_cpu_usage
        return super().add_active_spike(spike)

    def remove_active_spike(self, spike: ThreadSpikeInfo) -> None:
        """Remove active spike."""
        self.threads_spiked.remove(spike.thread_id)
        self.thread_cpu_usage -= spike.average_cpu_usage
        return super().remove_active_spike(spike)

    def __copy__(self) -> "ThreadSpikeChangeEvent":
        return ThreadSpikeChangeEvent(
                self.time, self.spikes_started.copy(), self.spikes_ended.copy(),
                self.spikes_active.copy(), self.threads_spiked.copy(), self.thread_cpu_usage)


@dataclass
class SpikeChangeEvents:
    """Events when spikes change their state (a spike starts or ends)."""
    events: list[SpikeChangeEvent] = field(default_factory=list)
    """List of events sorted by time."""
    _event_indices: list[datetime.datetime] = field(default_factory=list)
    """List of time indexes of events in the list.

    Every events[i] has its events[i].time at event_indices[i].
    """

    def _insert_event(self, index: int, event: SpikeChangeEvent) -> None:
        """Insert an event to the list."""
        self.events.insert(index, event)
        self._event_indices.insert(index, event.time)

    def _add_start_event_at_index(self, index: int, spike: SpikeInfo) -> None:
        """Add a start event to the list at a given index.

        The following existing events are not updated in this method. They will be updated in
        _add_end_event_at_index().

        Args:
            index:
                a) The spike start time is the same as the time of an existing event:
                    index of existing event to extend
                b) Other cases: index of new event to insert
            spike: Spike that started at the time of the event.
        """
        assert index >= 0, "Index is negative."
        insert_at_end = index >= len(self.events)
        if not insert_at_end and spike.start_time == self.events[index].time:
            self.events[index].add_start_event(spike)
        elif insert_at_end or spike.start_time < self.events[index].time:
            previous_event = None if index <= 0 else self.events[index - 1]
            event = SpikeChangeEvent.from_spike_start(spike, previous_event)
            self._insert_event(index, event)
        else:
            assert False, "Spike start time is later than the time of the event."

    def _add_end_event_at_index(
            self, index: int, index_of_start_event: int, spike: SpikeInfo) -> None:
        """Add an end event to the list at a given index.

        The events after index_of_start_event till this new event are updated.

        Args:
            index:
                a) The spike end time is the same as the time of an existing event:
                    index of existing event to extend
                b) Other cases: index of new event to insert
            index_of_start_event: Index of the start event of the spike.
            spike: Spike that ended at the time of the event.
        """
        assert index >= 0 and index_of_start_event >= 0, "Index is negative."
        assert index_of_start_event < index, "Start event is not before the end event."
        insert_at_end = index >= len(self.events)
        if not insert_at_end and spike.end_time == self.events[index].time:
            self.events[index].add_end_event(spike, remove_active_spike=False)
        elif insert_at_end or spike.end_time < self.events[index].time:
            previous_event = self.events[index - 1]
            event = SpikeChangeEvent.from_spike_end(spike, previous_event)
            self._insert_event(index, event)
        else:
            assert False, "Spike end time is later than the time of the event."
        for update_index in range(index_of_start_event + 1, index):
            self.events[update_index].add_active_spike(spike)

    def add_event(self, spike: SpikeInfo) -> None:
        """Add an event to the list, maintaining sorted order."""
        start_index = bisect.bisect_left(self._event_indices, spike.start_time)
        self._add_start_event_at_index(start_index, spike)
        end_index = bisect.bisect_left(self._event_indices, spike.end_time)
        self._add_end_event_at_index(end_index, start_index, spike)


def parse_log_file(log_file: str | Path) -> list[SpikeInfo]:
    """Parse a log file and return a list of spikes."""
    spikes: list[SpikeInfo] = []        # Redundant initialization needed to satisfy Pylance.
    with contextlib.ExitStack() as file_stack:
        if log_file == "-":
            log_file_handle = file_stack.enter_context(sys.stdin)
        else:
            log_file_handle = file_stack.enter_context(open(log_file, "r", encoding="utf-8"))
        spikes = [
                SpikeInfo.from_log(log_line)
                for log_line in log_file_handle
                if SpikeInfo.log_line_is_spike(log_line)
        ]
    return spikes


def print_newlines(count: int = 1) -> None:
    """Print newlines."""
    print("\n" * count, end="")


class SpikeStats:
    """Provide statistics about spikes."""
    spikes: list[SpikeInfo]
    """List of spikes."""
    kinds: Sequence[str]
    """Kinds of statistics to compute and show."""
    top_counts_limit: int
    """Limit the number of top counts to show."""
    spike_type_occurrence_counters: defaultdict[SpikeType, Counter[str]]
    """Counters of spike types by number of occurrences."""
    spike_type_cpu_seconds_counters: defaultdict[SpikeType, Counter[str]]
    """Counters of spike types by CPU seconds consumed.

    The Counter objects contains float values, while in typeshed it is hardcoded to int.
    """

    def reset_counters(self) -> None:
        """Reset counters."""
        self.spike_type_occurrence_counters = defaultdict(Counter)
        self.spike_type_cpu_seconds_counters = defaultdict(Counter)

    def __init__(self, spikes: list[SpikeInfo], kinds: Sequence[str], top_counts: int = -1) -> None:
        """Initialize the class."""
        self.spikes = spikes
        self.kinds = kinds
        self.top_counts_limit = top_counts
        self.reset_counters()

    def update_counters(self) -> None:
        """Update counters."""
        for spike in self.spikes:
            self.spike_type_occurrence_counters[spike.spike_type][spike.get_sub_type_str()] += 1
            # Note: Typeshed does not support non-int values for Counter.
            # The standard library does support it, though.
            self.spike_type_cpu_seconds_counters[
                    spike.spike_type][spike.get_sub_type_str()] += (    # type: ignore
                        spike.get_cpu_seconds())

    def print_time_range(self) -> None:
        """Print time range of logs."""
        print("Time range of logs:")
        print(f"    {self.spikes[0].record_time} - {self.spikes[-1].record_time}")

    def print_spike_type_occurrence_counters(self, newlines: int = 0) -> None:
        """Print spike type occurrence counters."""
        print_newlines(newlines)
        print("Spike types by number of occurrences:")
        for spike_type, sub_type_counter in self.spike_type_occurrence_counters.items():
            print(f"    {spike_type.value}:")
            for sub_type, sub_type_cpu_seconds in (
                    sub_type_counter.most_common(self.top_counts_limit)):
                print(f"        {sub_type:<20} {sub_type_cpu_seconds:>3}")

    def print_spike_type_cpu_seconds_counters(self, newlines: int = 0) -> None:
        """Print spike type CPU seconds counters."""
        print_newlines(newlines)
        print("Spike types by CPU seconds consumed:")
        for spike_type, sub_type_counter in self.spike_type_cpu_seconds_counters.items():
            print(f"    {spike_type.value}:")
            for sub_type, sub_type_cpu_seconds in (
                    sub_type_counter.most_common(self.top_counts_limit)):
                print(f"        {sub_type:<20} {sub_type_cpu_seconds:8.2f}")

    def print_spike_stats(self) -> None:
        """Print statistics about spikes."""
        self.print_time_range()
        if "type" in self.kinds:
            self.print_spike_type_occurrence_counters(newlines=1)
            self.print_spike_type_cpu_seconds_counters(newlines=1)


class SpikesInTime:
    """Store and process information about spikes evolving in time."""
    spikes: list[SpikeInfo]
    """List of spikes."""
    spike_change_events_cpu: SpikeChangeEvents
    """Events when CPU spikes change their state and the state in between."""
    spike_change_events_thread: SpikeChangeEvents
    """Events when thread spikes change their state and the state in between."""

    def __init__(self, spikes: list[SpikeInfo]) -> None:
        """Initialize the class."""
        self.spikes = spikes
        self.spike_change_events_cpu = SpikeChangeEvents()
        self.spike_change_events_thread = SpikeChangeEvents()

    def update(self) -> None:
        """Update spike change events."""
        for spike in self.spikes:
            if spike.spike_type == SpikeType.CPU:
                self.spike_change_events_cpu.add_event(spike)
            elif spike.spike_type == SpikeType.THREAD:
                self.spike_change_events_thread.add_event(spike)
            else:
                assert False, "Unknown spike type."


def parse_cli_args(args: Sequence[str]) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
            description="Analyze data from Check Point spike detective in /var/log/messages.")
    parser.add_argument(
            "log_file", type=str, help="Path to the log file to analyze.")
    parser.add_argument(
            "--stats", "-s", type=str, nargs="*", choices=["type"],
            help="Kinds of statistics to show.")
    parser.add_argument(
            "--top-counts", "-t", type=int, default=10,
            help="Limit the number of top counts to show.")
    return parser.parse_args(args)


def main(args: Sequence[str]) -> None:
    """Main function."""
    parsed_args = parse_cli_args(args[1:])
    spikes = parse_log_file(parsed_args.log_file)
    if parsed_args.stats is not None:
        spike_stats = SpikeStats(spikes, parsed_args.stats, parsed_args.top_counts)
        spike_stats.update_counters()
        spike_stats.print_spike_stats()
    spikes_in_time = SpikesInTime(spikes)
    spikes_in_time.update()


if __name__ == "__main__":
    main(sys.argv)
