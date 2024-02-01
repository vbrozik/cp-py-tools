"""Test the spike_analyzer script."""

from __future__ import annotations

import datetime

from resource_monitoring.spike_analyzer import CPUSpikeInfo, SpikeInfo, SpikeType, ThreadSpikeInfo


EXAMPLE_LOGS = [
    "Jan 30 10:13:07 2024 abc-dc3-firewall1 spike_detective: spike info: "
    "type: cpu, cpu core: 34, top consumer: cpviewd, "
    "start time: 30/01/24 10:13:00, spike duration (sec): 6, "
    "initial cpu usage: 81, average cpu usage: 81, perf taken: 1",

    "Jan 30 10:13:07 2024 abc-dc1-firewall4 spike_detective: spike info: "
    "type: thread, thread id: 143608, thread name: cpviewd, "
    "start time: 30/01/24 10:13:00, spike duration (sec): 6, "
    "initial cpu usage: 79, average cpu usage: 79, perf taken: 0",

    "Jan 30 10:17:03 2024 firewall_xyz spike_detective: spike info: "
    "type: cpu, cpu core: 6, top consumer: system interrupts, "
    "start time: 30/01/24 10:14:35, spike duration (sec): 147, "
    "initial cpu usage: 87, average cpu usage: 77, perf taken: 0",
    ]


def test_spike_info_from_log0():
    """Test case for the SpikeInfo.from_log() method, with UTC time zone."""
    log = EXAMPLE_LOGS[0]
    saved_time_zone = SpikeInfo.time_zone
    SpikeInfo.time_zone = datetime.timezone.utc
    spike_info = SpikeInfo.from_log(log)
    SpikeInfo.time_zone = saved_time_zone

    assert isinstance(spike_info, SpikeInfo)
    assert isinstance(spike_info, CPUSpikeInfo)
    assert spike_info.record_time == datetime.datetime(
            2024, 1, 30, 10, 13, 7, tzinfo=datetime.timezone.utc)
    assert spike_info.origin == "abc-dc3-firewall1"
    assert spike_info.spike_type == SpikeType.CPU
    assert spike_info.cpu_core == 34
    assert spike_info.top_consumer == "cpviewd"
    assert spike_info.start_time == datetime.datetime(
            2024, 1, 30, 10, 13, tzinfo=datetime.timezone.utc)
    assert spike_info.end_time == datetime.datetime(
            2024, 1, 30, 10, 13, 6, tzinfo=datetime.timezone.utc)
    assert spike_info.duration == 6
    assert spike_info.initial_cpu_usage == 81
    assert spike_info.average_cpu_usage == 81
    assert spike_info.perf_taken is True
    assert spike_info.original_log == log


def test_spike_info_from_log1():
    """Test case for the SpikeInfo.from_log() method with local time zone."""
    log = EXAMPLE_LOGS[1]
    local_time_zone = datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo
    spike_info = SpikeInfo.from_log(log)

    assert isinstance(spike_info, SpikeInfo)
    assert isinstance(spike_info, ThreadSpikeInfo)
    assert spike_info.record_time == datetime.datetime(
            2024, 1, 30, 10, 13, 7, tzinfo=local_time_zone)
    assert spike_info.origin == "abc-dc1-firewall4"
    assert spike_info.spike_type == SpikeType.THREAD
    assert spike_info.thread_id == 143608
    assert spike_info.thread_name == "cpviewd"
    assert spike_info.start_time == datetime.datetime(
            2024, 1, 30, 10, 13, tzinfo=local_time_zone)
    assert spike_info.end_time == datetime.datetime(
            2024, 1, 30, 10, 13, 6, tzinfo=local_time_zone)
    assert spike_info.duration == 6
    assert spike_info.initial_cpu_usage == 79
    assert spike_info.average_cpu_usage == 79
    assert spike_info.perf_taken is False
    assert spike_info.original_log == log


def test_spike_info_from_log2():
    """Test case for the SpikeInfo.from_log() method with a time zone given by an offset."""
    log = EXAMPLE_LOGS[2]
    saved_time_zone = SpikeInfo.time_zone
    time_zone = datetime.timezone(datetime.timedelta(hours=5))
    SpikeInfo.time_zone = time_zone
    spike_info = SpikeInfo.from_log(log)
    SpikeInfo.time_zone = saved_time_zone

    assert isinstance(spike_info, SpikeInfo)
    assert isinstance(spike_info, CPUSpikeInfo)
    assert spike_info.record_time == datetime.datetime(
            2024, 1, 30, 10, 17, 3, tzinfo=time_zone)
    assert spike_info.origin == "firewall_xyz"
    assert spike_info.spike_type == SpikeType.CPU
    assert spike_info.cpu_core == 6
    assert spike_info.top_consumer == "system interrupts"
    assert spike_info.start_time == datetime.datetime(
            2024, 1, 30, 10, 14, 35, tzinfo=time_zone)
    assert spike_info.end_time == datetime.datetime(
            2024, 1, 30, 10, 17, 2, tzinfo=time_zone)
    assert spike_info.duration == 147
    assert spike_info.initial_cpu_usage == 87
    assert spike_info.average_cpu_usage == 77
    assert spike_info.perf_taken is False
    assert spike_info.original_log == log


def test_log_line_is_spike():
    """Test case for the SpikeInfo.log_line_is_spike() method."""
    log_line = EXAMPLE_LOGS[0]
    assert SpikeInfo.log_line_is_spike(log_line) is True

    log_line = EXAMPLE_LOGS[1]
    assert SpikeInfo.log_line_is_spike(log_line) is True

    log_line = EXAMPLE_LOGS[2]
    assert SpikeInfo.log_line_is_spike(log_line) is True

    log_line = "Jan 30 10:20:00 2024 firewall_xyz some other log line"
    assert SpikeInfo.log_line_is_spike(log_line) is False
