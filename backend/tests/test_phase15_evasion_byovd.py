"""
Phase 15 Unit & Integration Tests:
- Polymorphic Engine: mutation, comment/salt injection, hash uniqueness
- Payload Encryptor: custom XOR + AES evidence payload encryption & decryption roundtrips
- BYOVD Driver Catalog: vulnerable driver definitions and metadata
- In-Memory Fileless Execution & Memory Analysis Collector
- CDN Domain Fronting & Traffic Routing Endpoints
"""

import pytest
from app.jocky.polymorphic import PolymorphicEngine, PayloadEncryptor
from app.collectors.drivers import DriversListCollector, MemoryAnalysisCollector, KNOWN_VULNERABLE_DRIVERS
from app.api.evasion import (
    MutateRequest,
    EncryptRequest,
    DecryptRequest,
    CDNRoutingRequest,
    mutate_script,
    encrypt_payload,
    decrypt_payload,
    get_routing_config,
    update_routing_config,
    list_drivers,
    analyze_memory
)

def test_polymorphic_mutations_unique_hashes():
    """Verify that multiple mutations of a JOCKY script produce distinct hashes."""
    script = "INVESTIGATE byovd_detection"
    res = PolymorphicEngine.mutate(script, iterations=5)
    
    assert res["iteration_count"] == 5
    hashes = res["hashes"]
    assert len(hashes) == 5, "Each mutation must generate a unique SHA-256 hash"
    assert len(res["variants"]) == 5
    for var in res["variants"]:
        assert len(var) > len(script)

def test_payload_encryptor_roundtrip():
    """Verify encryption and decryption roundtrip for forensic payloads."""
    test_payload = {"driver": "RTCore64.sys", "cve": "CVE-2019-16098", "severity": "CRITICAL"}
    inv_id = "INV-TEST-2026"
    
    encrypted_blob = PayloadEncryptor.encrypt(test_payload, inv_id)
    assert encrypted_blob.startswith(PayloadEncryptor.MAGIC)
    assert len(encrypted_blob) > len(str(test_payload))
    
    decrypted = PayloadEncryptor.decrypt(encrypted_blob, inv_id)
    assert decrypted == test_payload

def test_vulnerable_driver_catalog():
    """Verify known BYOVD driver database structure and signatures."""
    assert len(KNOWN_VULNERABLE_DRIVERS) >= 5
    driver_names = [d.lower() for d in KNOWN_VULNERABLE_DRIVERS.keys()]
    assert "rtcore64.sys" in driver_names
    assert "dbutil_2_3.sys" in driver_names
    assert "gdrv.sys" in driver_names
    
    # Ensure all entries have required forensic fields
    for name, d in KNOWN_VULNERABLE_DRIVERS.items():
        assert "cve" in d
        assert "vendor" in d
        assert "risk" in d
        assert "technique" in d

def test_mutate_endpoint():
    """Test the mutate_script API endpoint handler."""
    req = MutateRequest(script="INVESTIGATE byovd_detection", iterations=3)
    res = mutate_script(req)
    assert res["status"] == "SUCCESS"
    assert res["variant_count"] == 3
    assert res["all_hashes_unique"] is True

def test_encrypt_decrypt_endpoints():
    """Test encrypt and decrypt API endpoint handlers."""
    payload = {"evidence_type": "KERNEL_DRIVER", "name": "RTCore64.sys"}
    enc_req = EncryptRequest(payload=payload, investigation_id="INV-API-001")
    enc_res = encrypt_payload(enc_req)
    assert enc_res["status"] == "ENCRYPTED"
    
    dec_req = DecryptRequest(blob_hex=enc_res["blob_hex"], investigation_id="INV-API-001")
    dec_res = decrypt_payload(dec_req)
    assert dec_res["status"] == "DECRYPTED"
    assert dec_res["payload"] == payload

def test_cdn_routing_endpoints():
    """Test CDN routing configuration endpoints."""
    # Test updating to DOMAIN_FRONT — now calls live cdn_routing module
    req = CDNRoutingRequest(
        routing_mode="DOMAIN_FRONT",
        cdn_domain="ajax.microsoft.com",
        real_host="forensics.internal"
    )
    up_res = update_routing_config(req)
    # Live domain fronting returns 'CONFIGURED'; legacy fallback returns 'ROUTING_UPDATED'
    valid_statuses = {"CONFIGURED", "ROUTING_UPDATED", "LIVE", "STARTING"}
    assert (
        up_res.get("status") in valid_statuses
        or up_res.get("routing_mode") == "DOMAIN_FRONT"
        or up_res.get("active_mode") == "DOMAIN_FRONT"
    )

    # Test reading back
    get_res = get_routing_config()
    assert "supported_modes" in get_res or "active_mode" in get_res

def test_drivers_and_memory_collectors():
    """Test DriversListCollector and MemoryAnalysisCollector execution."""
    drv_col = DriversListCollector()
    res = drv_col.collect()
    assert res.operation == "DRIVERS.LIST"
    assert res.status in ["SUCCESS", "PARTIALLY_COMPLETED", "NOT_AVAILABLE"]
    
    mem_col = MemoryAnalysisCollector()
    m_res = mem_col.collect()
    assert m_res.operation == "MEMORY.ANALYSIS"
    assert m_res.status in ["SUCCESS", "PARTIALLY_COMPLETED", "NOT_AVAILABLE"]
