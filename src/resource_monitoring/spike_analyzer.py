#!/usr/bin/env python3

"""Analyze data from Check Point spike detective."""

import argparse
import bisect
import contextlib
import datetime
import enum
import functools
import re
import sys
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Iterator, NamedTuple, Sequence, Type


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
    duration: datetime.timedelta
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
                "duration": datetime.timedelta(seconds=int(data["duration"])),
                "initial_cpu_usage": int(data["initial_cpu_usage"]),
                "average_cpu_usage": int(data["average_cpu_usage"]),
                "perf_taken": bool(int(data["perf_taken"])),
                "original_log": log_line,
                }
        attributes["end_time"] = attributes["start_time"] + attributes["duration"]
        if attributes["spike_type"] == SpikeType.CPU:
            attributes["cpu_core"] = int(data["cpu_core"])
            attributes["top_consumer"] = data["top_consumer"]
            return SpikeInfoCPU(**attributes)
        elif attributes["spike_type"] == SpikeType.THREAD:
            attributes["thread_id"] = int(data["thread_id"])
            attributes["thread_name"] = data["thread_name"]
            return SpikeInfoThread(**attributes)
        raise ValueError("Unknown spike type.")

    @abstractmethod
    def get_sub_type_str(self) -> str:
        """Return a string with the sub-type of the spike."""
        pass

    def get_cpu_seconds(self) -> float:
        """Return CPU seconds used by the spike."""
        return self.duration.seconds * self.average_cpu_usage / 100


@dataclass(frozen=True)
class SpikeInfoCPU(SpikeInfo):
    """Information about a CPU spike."""
    cpu_core: int
    """CPU core number that spiked if the type is CPU."""
    top_consumer: str
    """Top consumer that spiked if the type is CPU."""

    def get_sub_type_str(self) -> str:
        """Return a string with the sub-type of the spike."""
        return f"{self.cpu_core:2d}"


@dataclass(frozen=True)
class SpikeInfoThread(SpikeInfo):
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
    """Event when spikes change their state (a spike starts or ends).

    These events are used to describe the state of spikes between two changes.
    """
    time: datetime.datetime
    """Time of the event."""
    spikes_started: set[SpikeInfo] = field(default_factory=set)
    """List of spikes that started at the time of the event."""
    spikes_ended: set[SpikeInfo] = field(default_factory=set)
    """List of spikes that ended at the time of the event."""
    spikes_active: set[SpikeInfo] = field(default_factory=set)
    """List of spikes that were active at least from the time of the event till the next event."""
    cpu_usage: int = 0
    """CPU usage of CPUs or threads at the time of the event as a sum of average CPU usages."""

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

    def add_start_event(self, spike: SpikeInfo) -> None:
        """Add a start event to the list."""
        self.spikes_started.add(spike)

    def add_end_event(self, spike: SpikeInfo) -> None:
        """Add an spike end event to the event."""
        self.spikes_ended.add(spike)

    def update_sums(self) -> None:
        """Update the sums of spikes."""
        self.cpu_usage = sum(spike.average_cpu_usage for spike in self.spikes_active)


@dataclass
class SpikeChangeEventCPU(SpikeChangeEvent):
    """Event when CPU spikes change their state (a spike starts or ends)."""
    cpus_spiked: set[int] = field(default_factory=set)
    """List of CPU cores that spiked at the time of the event."""

    def __copy__(self) -> "SpikeChangeEventCPU":
        # Note: Is there a way to use super() here?
        return SpikeChangeEventCPU(
                self.time, self.spikes_started.copy(), self.spikes_ended.copy(),
                self.spikes_active.copy(), self.cpu_usage, self.cpus_spiked.copy())  # type: ignore
        # TODO: Resolve variance of self.spikes_active

    def update_sums(self) -> None:
        """Update the sums of spikes."""
        self.spikes_active: set[SpikeInfoCPU]
        self.cpus_spiked = {spike.cpu_core for spike in self.spikes_active}
        return super().update_sums()


@dataclass
class SpikeChangeEventThread(SpikeChangeEvent):
    """Event when thread spikes change their state (a spike starts or ends)."""
    threads_spiked: set[int] = field(default_factory=set)
    """List of thread IDs that spiked at the time of the event."""

    def __copy__(self) -> "SpikeChangeEventThread":
        return SpikeChangeEventThread(
                self.time, self.spikes_started.copy(), self.spikes_ended.copy(),
                self.spikes_active.copy(), self.cpu_usage,      # type: ignore
                self.threads_spiked.copy())

    def update_sums(self) -> None:
        """Update the sums of spikes."""
        self.spikes_active: set[SpikeInfoThread]
        self.threads_spiked = {spike.thread_id for spike in self.spikes_active}
        return super().update_sums()


def round_time(
        time: datetime.datetime, time_step: datetime.timedelta, up: bool = False,
        ) -> datetime.datetime:
    """Round time to the nearest time step. Zero time step is at midnight."""
    midnight_base = datetime.datetime(time.year, time.month, time.day, tzinfo=time.tzinfo)
    time_diff = time - midnight_base
    time_rounding_diff = - (time_diff % time_step)
    if up:
        time_rounding_diff += time_step
    return time + time_rounding_diff


def get_time_interval_overlap_fraction(
        base_interval: Sequence[datetime.datetime], other_interval: Sequence[datetime.datetime]
        ) -> float:
    """Return the overlap of two time intervals as fraction of the first interval."""
    start = max(base_interval[0], other_interval[0])
    end = min(base_interval[1], other_interval[1])
    overlap = max(datetime.timedelta(), (end - start))
    return overlap / (base_interval[1] - base_interval[0])


class SpikeChangeEventPart(NamedTuple):
    """Part of a spike change event defined as a fraction of the event."""
    spike_event: SpikeChangeEvent
    """Spike change event describing state of spikes between two changes."""
    overlap_fraction: float
    """Fraction of the event which makes this part."""


@dataclass
class SpikesState:
    """State of spikes during a given time period independent of spike change events.

    The state can be stored either for a CPU spike or a thread spike.
    """
    time: datetime.datetime
    """Start time of the period the state is for."""
    length: datetime.timedelta
    """Length of the period in seconds the state is for."""
    spike_event_parts: list[SpikeChangeEventPart]
    """Events when spikes change their state during the time period."""
    max_concurrent_spikes: int = field(init=False)
    """Maximum number of concurrent spikes."""
    max_cpu_usage_from_spike_average: int = field(init=False)
    """Maximum CPU usage from average CPU usage of the spikes."""
    cpu_seconds_usage: float = field(init=False)
    """Total CPU seconds used by the spikes."""
    max_spike_duration: datetime.timedelta = field(init=False)
    """Maximum length of a spike (possibly extending from the time period)."""

    def __post_init__(self) -> None:
        """Compute the statistics fields."""
        self.max_concurrent_spikes = max(
                len(part.spike_event.spikes_active) for part in self.spike_event_parts)
        self.max_cpu_usage_from_spike_average = max((
                spike.average_cpu_usage
                for event, _fraction in self.spike_event_parts
                for spike in event.spikes_active), default=0)
        self.cpu_seconds_usage = sum(
                spike.get_cpu_seconds() * fraction
                for event, fraction in self.spike_event_parts
                for spike in event.spikes_active)
        self.max_spike_duration = max((
                spike.duration
                for event, _fraction in self.spike_event_parts
                for spike in event.spikes_active), default=datetime.timedelta())

    def __str__(self) -> str:
        """Return a string representation of the state."""
        return f"{self.time} {self.max_concurrent_spikes:2d} {self.cpu_seconds_usage:8.2f} "


@dataclass
class SpikeChangeEvents:
    """Events when spikes change their state (a spike starts or ends).

    The events are sorted by time. The structure should contain only event of a single type.
    """
    SpikeType: Type[SpikeInfo]
    """Type of spikes the events are for."""
    events: list[SpikeChangeEvent] = field(default_factory=list)
    """List of events sorted by time."""
    _event_indices: list[datetime.datetime] = field(default_factory=list)
    """List of time indexes of events in the list.

    Every events[i] has its events[i].time at event_indices[i].
    """
    SpikeChangeEventType: Type[SpikeChangeEvent] = field(init=False)

    def __post_init__(self) -> None:
        """Set the type of SpikeChangeEvent to use."""
        if self.SpikeType == SpikeInfoCPU:
            self.SpikeChangeEventType = SpikeChangeEventCPU
        elif self.SpikeType == SpikeInfoThread:
            self.SpikeChangeEventType = SpikeChangeEventThread
        else:
            assert False, "Unknown spike type."

    def _insert_event(self, index: int, event: SpikeChangeEvent) -> None:
        """Insert an event to the list."""
        self.events.insert(index, event)
        self._event_indices.insert(index, event.time)

    def _add_start_event_at_index(self, index: int, spike: SpikeInfo) -> None:
        """Add a start event to the list at a given index.

        Args:
            index:
                a) The spike start time is the same as the time of an existing event:
                    index of existing event to extend
                b) Other cases: index of new event to insert
            spike: Spike that started at the time of the event.
        """
        assert index >= 0, "Cannot add event at negative index."
        insert_at_end = index >= len(self.events)
        if not insert_at_end and spike.start_time == self.events[index].time:
            self.events[index].add_start_event(spike)       # Extend the existing event.
        elif insert_at_end or spike.start_time < self.events[index].time:
            event = self.SpikeChangeEventType(spike.start_time, {spike})
            self._insert_event(index, event)
        else:
            assert False, "Spike start time is later than the time of the event."

    def _add_end_event_at_index(
            self, index: int, index_of_start_event: int, spike: SpikeInfo) -> None:
        """Add an end event to the list at a given index.

        Args:
            index:
                a) The spike end time is the same as the time of an existing event:
                    index of existing event to extend
                b) Other cases: index of new event to insert
            index_of_start_event: Index of the start event of the spike.
            spike: Spike that ended at the time of the event.
        """
        assert index >= 0 and index_of_start_event >= 0, "Cannot add event at negative index."
        assert index_of_start_event < index, "Start event is not before the end event."
        insert_at_end = index >= len(self.events)
        if not insert_at_end and spike.end_time == self.events[index].time:
            self.events[index].add_end_event(spike)
        elif insert_at_end or spike.end_time < self.events[index].time:
            event = self.SpikeChangeEventType(spike.end_time, set(), {spike})
            self._insert_event(index, event)
        else:
            assert False, "Spike end time is later than the time of the event."

    def add_event(self, spike: SpikeInfo) -> None:
        """Add an event to the list, maintaining sorted order.

        This method does not set active spikes in the events.
        """
        assert isinstance(spike, self.SpikeType), "Spike type does not match the event type."
        assert spike.start_time < spike.end_time, "Spike start time is not before the end time."
        start_index = bisect.bisect_left(self._event_indices, spike.start_time)
        self._add_start_event_at_index(start_index, spike)
        end_index = bisect.bisect_left(self._event_indices, spike.end_time, start_index)
        self._add_end_event_at_index(end_index, start_index, spike)

    def update_active_spikes(self) -> None:
        """Update active spikes in the events."""
        active_spikes: set[SpikeInfo] = set()
        for event in self.events:
            assert not event.spikes_started & event.spikes_ended, (
                    "Started and ended spikes overlap.")
            assert not event.spikes_started & active_spikes, "Started spike already active."
            assert not event.spikes_ended - active_spikes, "Ended inactive spike."
            active_spikes |= event.spikes_started
            active_spikes -= event.spikes_ended
            event.spikes_active = set(active_spikes)
            event.update_sums()
        assert not active_spikes, "There are active spikes after the last event."

    def iterate_in_time_steps(
            self, time_step: datetime.timedelta, round_start_time: bool = True
            ) -> Iterator[SpikesState]:
        """Iterate over events in time steps yielding events in each time step.

        Events which are in the time step only partially has the float value indicating the
        fraction of the time step they are in (others are naturally 1.0).
        """
        if not self.events:
            return
        if len(self.events) == 1:
            assert False, "SpikeChangeEvents has only one event but there must be at least two."
        start_time = self.events[0].time
        if round_start_time:
            start_time = round_time(start_time, time_step)
        assert not self.events[-1].spikes_active, "Last event must end all spikes but does not."
        current_interval = [start_time, start_time + time_step]
        event_iterator = iter(self.events)
        events_in_interval: list[SpikeChangeEvent] = []
        # FIFO of events being processed. Last item is outside the interval.
        processing_phase = 0
        while True:
            events_to_yield: list[SpikeChangeEventPart] = []
            for event in event_iterator:
                events_in_interval.append(event)
                while len(events_in_interval) > 1:  # Do we need loop or just a single check?
                    overlap_fraction = get_time_interval_overlap_fraction(
                        current_interval, [events_in_interval[0].time, events_in_interval[1].time])
                    if overlap_fraction > 0:
                        events_to_yield.append(
                                SpikeChangeEventPart(events_in_interval[0], overlap_fraction))
                    events_in_interval.pop(0)
                if event.time >= current_interval[1]:   # We have crossed the end of the interval.
                    break
            else:
                event_iterator = iter((
                        SpikeChangeEvent(current_interval[1], set(), set(), set()),))
                processing_phase += 1
            if events_to_yield:     # Is the condition needed?
                yield SpikesState(current_interval[0], time_step, events_to_yield)
            if processing_phase >= 2:
                break
            current_interval = [current_interval[1], current_interval[1] + time_step]


class SpikesStateInTime:
    """Store and process information about spikes evolving in time."""
    spikes: list[SpikeInfo]
    """List of spikes."""
    spike_change_events_cpu: SpikeChangeEvents
    """Events when CPU spikes change their state and the state in between."""
    spike_change_events_thread: SpikeChangeEvents
    """Events when thread spikes change their state and the state in between."""

    def __init__(self, spikes: list[SpikeInfo]) -> None:
        """Initialize the class."""


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
    spikes_in_time_cpu: list[SpikesState]
    """State of CPU spikes in time."""
    spikes_in_time_thread: list[SpikesState]
    """State of thread spikes in time."""
    time_step: ClassVar[datetime.timedelta] = datetime.timedelta(minutes=10)
    """Time step to use for processing the spikes to spikes_in_time_* lists."""

    def __init__(self, spikes: list[SpikeInfo]) -> None:
        """Initialize the class."""
        self.spikes = spikes
        self.spike_change_events_cpu = SpikeChangeEvents(SpikeInfoCPU)
        self.spike_change_events_thread = SpikeChangeEvents(SpikeInfoThread)
        self.spikes_in_time_cpu = []
        self.spikes_in_time_thread = []

    def update(self) -> None:
        """Update spike change events."""
        for spike in self.spikes:
            if spike.spike_type == SpikeType.CPU:
                self.spike_change_events_cpu.add_event(spike)
                self.spike_change_events_cpu.update_active_spikes()
            elif spike.spike_type == SpikeType.THREAD:
                self.spike_change_events_thread.add_event(spike)
                self.spike_change_events_thread.update_active_spikes()
            else:
                assert False, "Unknown spike type."
        self.spikes_in_time_cpu = list(
                self.spike_change_events_cpu.iterate_in_time_steps(self.time_step))
        self.spikes_in_time_thread = list(
                self.spike_change_events_thread.iterate_in_time_steps(self.time_step))

    def print_spikes_in_time(self) -> None:
        """Print spikes in time."""
        print("CPU Spikes:")
        for spikes_in_time in self.spikes_in_time_cpu:
            print(spikes_in_time)
        print("Thread Spikes:")
        for spikes_in_time in self.spikes_in_time_thread:
            print(spikes_in_time)


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
    spikes_in_time.print_spikes_in_time()


if __name__ == "__main__":
    main(sys.argv)
