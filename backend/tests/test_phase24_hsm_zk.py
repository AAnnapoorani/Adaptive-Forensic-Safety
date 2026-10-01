import pytest
from app.core.hsm_signer import HSMSigner, ZeroKnowledgeEvidenceProver

def test_hsm_signer_keypair_and_signing():
    """Verify HSMSigner creates Ed25519 keys and signs messages tamper-evidently."""
    signer = HSMSigner(token_label="TEST-HSM")
    pub_bytes = signer.get_public_key_bytes()
    pub_hex = signer.get_public_key_hex()

    assert len(pub_bytes) == 32
    assert len(pub_hex) == 64

    message = b"JOCKY-EVIDENCE-RECORD-HASH-MANIFEST-2026"
    sig = signer.sign(message)
    assert len(sig) == 64

    # Verify signature
    assert signer.verify(message, sig) is True

    # Tampered message must fail verification
    assert signer.verify(b"TAMPERED-MESSAGE", sig) is False


def test_zero_knowledge_evidence_commitment():
    """Verify ZK commitments prove artifact integrity without revealing payload."""
    payload = b'{"suspicious_process": "mimikatz.exe", "vad_rwx": "0x7FFE0000"}'
    artifact_id = "ART-20261001-001"

    commitment_data = ZeroKnowledgeEvidenceProver.generate_evidence_commitment(
        payload_bytes=payload,
        artifact_id=artifact_id
    )

    assert "commitment" in commitment_data
    assert "blinding_salt" in commitment_data
    assert "payload_sha256" in commitment_data

    # Valid verification
    assert ZeroKnowledgeEvidenceProver.verify_commitment(
        commitment=commitment_data["commitment"],
        payload_hash=commitment_data["payload_sha256"],
        artifact_id=artifact_id,
        blinding_salt=commitment_data["blinding_salt"]
    ) is True

    # Tampered hash must fail verification
    assert ZeroKnowledgeEvidenceProver.verify_commitment(
        commitment=commitment_data["commitment"],
        payload_hash="0000000000000000000000000000000000000000000000000000000000000000",
        artifact_id=artifact_id,
        blinding_salt=commitment_data["blinding_salt"]
    ) is False


def test_zero_knowledge_indicator_proof():
    """Verify ZK indicator proofs confirm threat rule matching without exposing context."""
    payload = b'{"command_line": "powershell.exe -enc SQBFAFgA..."}'
    indicator = "POWERSHELL_ENCODED_EXECUTION"
    salt = "secret_investigation_salt_12345"

    proof = ZeroKnowledgeEvidenceProver.create_zk_indicator_proof(
        payload_bytes=payload,
        matched_indicator=indicator,
        secret_blinding_factor=salt
    )

    assert proof["verified"] is True
    assert "proof_token" in proof

    # Verification passes with valid token and hashes
    valid = ZeroKnowledgeEvidenceProver.verify_zk_indicator_proof(
        proof_token=proof["proof_token"],
        payload_hash=proof["payload_hash"],
        indicator_hash=proof["indicator_hash"],
        secret_blinding_factor=salt
    )
    assert valid is True

    # Altering the indicator hash must fail verification
    invalid = ZeroKnowledgeEvidenceProver.verify_zk_indicator_proof(
        proof_token=proof["proof_token"],
        payload_hash=proof["payload_hash"],
        indicator_hash="forged_indicator_hash",
        secret_blinding_factor=salt
    )
    assert invalid is False
