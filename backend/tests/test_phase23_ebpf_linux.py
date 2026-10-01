import pytest
from app.collectors.registry import get_collector, list_supported_operations
from app.collectors.ebpf_linux import LinuxEbpfCollector

def test_ebpf_collector_registration():
    """Verify EBPF.TRACE is properly registered in collector registry."""
    ops = list_supported_operations()
    assert "EBPF.TRACE" in ops
    
    collector = get_collector("EBPF.TRACE")
    assert collector is not None
    assert isinstance(collector, LinuxEbpfCollector)
    assert collector.operation == "EBPF.TRACE"


def test_ebpf_collector_execution_with_lotl_fallback():
    """Verify eBPF collector executes cleanly and produces LotL telemetry on Windows/Linux."""
    collector = LinuxEbpfCollector()
    res = collector.collect({"limit": 5})

    assert res.status == "SUCCESS"
    assert res.collector_name == collector.name
    assert res.operation == "EBPF.TRACE"
    assert isinstance(res.data, list)
    assert len(res.data) > 0
    assert "tracepoint" in res.data[0]
    assert "pid" in res.data[0]
    assert "ring_buffer_seq" in res.data[0]
    assert "tracepoints_monitored" in res.metadata
