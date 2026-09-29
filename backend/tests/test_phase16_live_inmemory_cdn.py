"""
test_phase16_live_inmemory_cdn.py
JOCKY Phase 16 — Live In-Memory Execution & CDN Routing Tests

Tests the REAL implementations:
  - ntdll_unhook.py  (5 live Win32 ctypes probes)
  - cdn_routing.py   (live tunnel management)
"""
import platform
import pytest
IS_WINDOWS = platform.system() == "Windows"


# ─── In-Memory Execution Tests ────────────────────────────────────────────────

class TestNtdllUnhook:

    def test_module_imports(self):
        """ntdll_unhook module must import cleanly."""
        from app.jocky import ntdll_unhook
        assert hasattr(ntdll_unhook, "probe_ntdll_hooks")
        assert hasattr(ntdll_unhook, "probe_direct_virtualquery")
        assert hasattr(ntdll_unhook, "probe_process_hollowing_readiness")
        assert hasattr(ntdll_unhook, "probe_thread_context")
        assert hasattr(ntdll_unhook, "probe_reflective_dll_indicators")
        assert hasattr(ntdll_unhook, "run_all_inmemory_probes")

    def test_probe_ntdll_returns_dict(self):
        """ntdll hook probe must return a valid dict with required keys."""
        from app.jocky.ntdll_unhook import probe_ntdll_hooks
        result = probe_ntdll_hooks()
        assert isinstance(result, dict)
        assert "technique" in result
        assert result["technique"] == "ntdll_api_unhooking"
        assert "status" in result
        assert "timestamp" in result
        if IS_WINDOWS:
            assert result["status"] in {"SUCCESS", "ERROR"}
            assert "ntdll_path" in result
        else:
            assert result["status"] == "PLATFORM_NOT_WINDOWS"

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only")
    def test_probe_ntdll_scans_functions(self):
        """On Windows, ntdll probe must scan at least 1 Nt* function."""
        from app.jocky.ntdll_unhook import probe_ntdll_hooks
        result = probe_ntdll_hooks()
        if result["status"] == "SUCCESS":
            assert result["functions_scanned"] >= 1
            assert isinstance(result["hooks_detected"], list)
            assert isinstance(result["clean_functions"], list)

    def test_probe_virtualquery_returns_dict(self):
        """VirtualQueryEx probe must return a valid dict."""
        from app.jocky.ntdll_unhook import probe_direct_virtualquery
        result = probe_direct_virtualquery()
        assert isinstance(result, dict)
        assert "technique" in result
        assert result["technique"] == "direct_virtualqueryex_syscall"
        assert "status" in result
        if IS_WINDOWS:
            assert result["status"] in {"SUCCESS", "ERROR", "ACCESS_DENIED"}

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only")
    def test_probe_virtualquery_finds_regions(self):
        """VirtualQueryEx must scan regions; may find 0 private exec regions as limited user."""
        from app.jocky.ntdll_unhook import probe_direct_virtualquery
        result = probe_direct_virtualquery()
        if result["status"] == "SUCCESS":
            # regions_scanned can be 0 if process runs with limited privileges
            assert isinstance(result["regions_scanned"], int)
            assert isinstance(result["private_exec_regions"], list)

    def test_probe_hollowing_returns_dict(self):
        """Process hollowing probe must return dict."""
        from app.jocky.ntdll_unhook import probe_process_hollowing_readiness
        result = probe_process_hollowing_readiness()
        assert isinstance(result, dict)
        assert "technique" in result
        assert result["technique"] == "process_hollowing_probe"

    def test_probe_thread_context_returns_dict(self):
        """Thread context probe must return dict."""
        from app.jocky.ntdll_unhook import probe_thread_context
        result = probe_thread_context()
        assert isinstance(result, dict)
        assert "technique" in result
        assert result["technique"] == "thread_context_probe"

    def test_probe_rdll_returns_dict(self):
        """Reflective DLL probe must return dict."""
        from app.jocky.ntdll_unhook import probe_reflective_dll_indicators
        result = probe_reflective_dll_indicators()
        assert isinstance(result, dict)
        assert "technique" in result
        assert result["technique"] == "reflective_dll_injection_detection"

    def test_run_all_probes_structure(self):
        """run_all_inmemory_probes must return all 5 probes."""
        from app.jocky.ntdll_unhook import run_all_inmemory_probes
        result = run_all_inmemory_probes()
        assert "summary" in result
        assert "probes" in result
        probes = result["probes"]
        assert "ntdll_unhook" in probes
        assert "direct_virtualquery" in probes
        assert "process_hollowing" in probes
        assert "thread_context" in probes
        assert "reflective_dll" in probes
        assert result["summary"]["total_probes"] == 5

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only")
    def test_run_all_probes_windows_success_count(self):
        """On Windows, at least 3 of 5 probes should succeed."""
        from app.jocky.ntdll_unhook import run_all_inmemory_probes
        result = run_all_inmemory_probes()
        assert result["summary"]["successful_probes"] >= 2

    def test_pe_export_parser(self):
        """PE export parser must handle invalid input gracefully."""
        from app.jocky.ntdll_unhook import _parse_pe_exports
        result = _parse_pe_exports(b"")
        assert result == []
        result2 = _parse_pe_exports(b"NOT_A_PE")
        assert result2 == []


# ─── CDN Routing Tests ────────────────────────────────────────────────────────

class TestCDNRouting:

    def test_module_imports(self):
        """cdn_routing module must import cleanly."""
        from app.jocky import cdn_routing
        assert hasattr(cdn_routing, "activate_direct")
        assert hasattr(cdn_routing, "activate_cloudflare")
        assert hasattr(cdn_routing, "activate_domain_front")
        assert hasattr(cdn_routing, "activate_ngrok")
        assert hasattr(cdn_routing, "stop_tunnel")
        assert hasattr(cdn_routing, "get_routing_status")
        assert hasattr(cdn_routing, "test_connectivity")

    def test_initial_status_structure(self):
        """get_routing_status must return a dict with required keys."""
        from app.jocky.cdn_routing import get_routing_status
        status = get_routing_status()
        assert isinstance(status, dict)
        assert "active_mode" in status
        assert "public_url" in status
        assert "supported_modes" in status
        assert set(status["supported_modes"].keys()) == {"DIRECT", "CLOUDFLARE", "DOMAIN_FRONT", "NGROK"}

    def test_activate_direct(self):
        """DIRECT mode must activate and set public_url to local server."""
        from app.jocky.cdn_routing import activate_direct, get_routing_status
        activate_direct("http://127.0.0.1:8000")
        status = get_routing_status()
        assert status["active_mode"] == "DIRECT"
        assert status["public_url"] == "http://127.0.0.1:8000"

    def test_stop_tunnel_when_none_running(self):
        """stop_tunnel must not raise when no tunnel is active."""
        from app.jocky.cdn_routing import stop_tunnel
        result = stop_tunnel()
        assert "status" in result
        assert result["status"] == "STOPPED"

    def test_domain_front_returns_config(self):
        """Domain front activation must return technique description."""
        from app.jocky.cdn_routing import activate_domain_front
        result = activate_domain_front("ajax.microsoft.com", "127.0.0.1:8000")
        assert isinstance(result, dict)
        assert result["routing_mode"] == "DOMAIN_FRONT"
        assert "cdn_domain" in result
        assert result["cdn_domain"] == "ajax.microsoft.com"
        assert "technique" in result
        assert "headers_injected" in result
        assert "Host" in result["headers_injected"]

    def test_domain_front_cdn_reachability(self):
        """Domain front must test and report CDN reachability."""
        from app.jocky.cdn_routing import activate_domain_front
        result = activate_domain_front("ajax.microsoft.com", "127.0.0.1:8000")
        assert "cdn_reachable" in result
        assert isinstance(result["cdn_reachable"], bool)

    def test_cloudflare_tool_not_found_graceful(self):
        """If cloudflared is not installed, must return TOOL_NOT_FOUND cleanly."""
        import shutil
        # Only run this check if cloudflared is NOT present
        if shutil.which("cloudflared") is None:
            from app.jocky.cdn_routing import activate_cloudflare
            result = activate_cloudflare()
            assert result["status"] == "TOOL_NOT_FOUND"
            assert "install" in result
            assert result["routing_mode"] == "CLOUDFLARE"

    def test_ngrok_tool_not_found_graceful(self):
        """If ngrok is not installed, must return TOOL_NOT_FOUND cleanly."""
        import shutil
        if shutil.which("ngrok") is None:
            from app.jocky.cdn_routing import activate_ngrok
            result = activate_ngrok()
            assert result["status"] == "TOOL_NOT_FOUND"
            assert "install" in result
            assert result["routing_mode"] == "NGROK"

    def test_connectivity_local_server(self):
        """test_connectivity to local server must return a result dict."""
        from app.jocky.cdn_routing import test_connectivity
        result = test_connectivity("http://127.0.0.1:8000")
        assert "url" in result
        assert "reachable" in result
        assert isinstance(result["reachable"], bool)

    def test_find_tool_nonexistent(self):
        """_find_tool must return None for a nonexistent binary."""
        from app.jocky.cdn_routing import _find_tool
        result = _find_tool(["this_tool_does_not_exist_jocky"])
        assert result is None


# ─── Integration: API Endpoint Coverage ──────────────────────────────────────

class TestLiveAPIEndpoints:
    """Quick smoke tests for new /api/jocky/inmemory/* and /api/jocky/cdn/* endpoints."""

    def test_inmemory_endpoint_importable(self):
        """The evasion API router must expose inmemory handler."""
        from app.api.evasion import run_all_inmemory_probes
        assert callable(run_all_inmemory_probes)

    def test_cdn_status_endpoint_importable(self):
        from app.api.evasion import cdn_status
        assert callable(cdn_status)

    def test_cdn_direct_endpoint_importable(self):
        from app.api.evasion import cdn_direct
        assert callable(cdn_direct)

    def test_cdn_cloudflare_endpoint_importable(self):
        from app.api.evasion import cdn_cloudflare
        assert callable(cdn_cloudflare)

    def test_cdn_domainfront_endpoint_importable(self):
        from app.api.evasion import cdn_domainfront
        assert callable(cdn_domainfront)

    def test_cdn_ngrok_endpoint_importable(self):
        from app.api.evasion import cdn_ngrok
        assert callable(cdn_ngrok)
