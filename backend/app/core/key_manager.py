"""
JOCKY Forensic Evidence Integrity 2.0 — Ed25519 Key Management & Digital Signer
Implements production-grade asymmetric key generation, rotation, export, and
tamper-evident signing conforming to NIST / RFC 8032 Ed25519 specifications.
"""

import os
import json
import uuid
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Key store directory resolution (defaults to ~/.jocky/keys to isolate from git)
_DEFAULT_KEY_DIR = Path(os.getenv("JOCKY_KEY_DIR", str(Path.home() / ".jocky" / "keys")))


class JockyKeyManager:
    """
    Manages JOCKY Ed25519 cryptographic signing keys:
    - Generates and persists Ed25519 key pairs with secure filesystem permissions (0o600)
    - Signs evidence records and chain tips
    - Verifies digital signatures against active or historical public keys
    - Supports perpetual key rotation (historical keys remain verifiable via key registry)
    - Strictly forbids private key exposure via logs or API responses
    """

    def __init__(self, key_dir: Path | str | None = None):
        self.key_dir = Path(key_dir) if key_dir else _DEFAULT_KEY_DIR
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.registry_file = self.key_dir / "key_registry.json"
        self._ensure_registry()

    def _ensure_registry(self) -> None:
        """Initialize key registry if missing, and secure its permissions."""
        if not self.registry_file.exists():
            initial_data = {
                "active_key_id": None,
                "keys": {}
            }
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump(initial_data, f, indent=2)
            try:
                os.chmod(self.registry_file, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass

    def _load_registry(self) -> dict[str, Any]:
        try:
            with open(self.registry_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    data = {"active_key_id": None, "keys": {}}
                if "keys" not in data or not isinstance(data["keys"], dict):
                    if isinstance(data.get("keys"), list):
                        converted = {}
                        for k in data["keys"]:
                            if isinstance(k, dict) and "key_id" in k:
                                converted[k["key_id"]] = k
                        data["keys"] = converted
                    else:
                        data["keys"] = {}
                return data
        except Exception:
            return {"active_key_id": None, "keys": {}}

    def _save_registry(self, data: dict[str, Any]) -> None:
        with open(self.registry_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def generate_key_pair(self, alias: str | None = None) -> str:
        """
        Generate a new Ed25519 key pair, persist it with restricted permissions,
        and mark it as the current active signing key. Returns key_id.
        """
        date_str = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
        rand_suffix = uuid.uuid4().hex[:6].upper()
        key_id = f"JOCKY-KEY-{date_str}-{rand_suffix}"
        
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()

        # Serialize private key to PKCS#8 PEM
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key to SubjectPublicKeyInfo PEM
        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Raw public bytes (32 bytes hex)
        pub_raw = pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()

        # Save private key file
        priv_file = self.key_dir / f"{key_id}.priv.pem"
        with open(priv_file, "wb") as f:
            f.write(priv_pem)
        
        # Enforce strict user-only read/write permissions
        try:
            os.chmod(priv_file, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

        # Save public key file
        pub_file = self.key_dir / f"{key_id}.pub.pem"
        with open(pub_file, "wb") as f:
            f.write(pub_pem)

        # Record in registry
        created_at = datetime.now(tz=timezone.utc).isoformat()
        registry = self._load_registry()
        registry["active_key_id"] = key_id
        registry["keys"][key_id] = {
            "key_id": key_id,
            "alias": alias or f"JOCKY Signing Key {date_str}",
            "created_at": created_at,
            "public_key_hex": pub_raw,
            "public_key_pem": pub_pem.decode("utf-8"),
            "status": "ACTIVE"
        }
        self._save_registry(registry)
        return key_id

    def get_or_create_active_key(self, alias: str | None = None) -> str:
        """Retrieve active key ID or generate one if registry is empty."""
        registry = self._load_registry()
        active_id = registry.get("active_key_id")
        if active_id and (self.key_dir / f"{active_id}.priv.pem").exists():
            return active_id
        return self.generate_key_pair(alias=alias or "JOCKY Default Primary Key")

    def rotate_key(self, alias: str | None = None) -> str:
        """
        Rotate active signing key: Generates a new active key while preserving
        historical public keys in the registry for backwards verification.
        """
        registry = self._load_registry()
        old_key = registry.get("active_key_id")
        if old_key and old_key in registry["keys"]:
            registry["keys"][old_key]["status"] = "RETIRED"
            registry["keys"][old_key]["retired_at"] = datetime.now(tz=timezone.utc).isoformat()
            self._save_registry(registry)

        new_key_id = self.generate_key_pair(alias=alias or "Rotated Key")
        return new_key_id

    def _load_private_key(self, key_id: str) -> ed25519.Ed25519PrivateKey:
        priv_file = self.key_dir / f"{key_id}.priv.pem"
        if not priv_file.exists():
            raise FileNotFoundError(f"Signing private key file for {key_id} not found.")
        with open(priv_file, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)  # type: ignore

    def sign_bytes(self, data: bytes, key_id: str | None = None) -> bytes:
        """Sign binary data using specified key (or active key). Returns raw 64-byte Ed25519 signature."""
        active_id = key_id or self.get_or_create_active_key()
        priv_key = self._load_private_key(active_id)
        return priv_key.sign(data)

    def sign_hex(self, data: bytes, key_id: str | None = None) -> tuple[str, str]:
        """Sign data and return (signature_hex, key_id)."""
        active_id = key_id or self.get_or_create_active_key()
        sig = self.sign_bytes(data, active_id)
        return sig.hex(), active_id

    def sign_data(self, data: bytes, key_id: str | None = None) -> str:
        """Sign data and return signature_hex."""
        sig_hex, _ = self.sign_hex(data, key_id)
        return sig_hex

    def verify_signature(
        self,
        signature: bytes | str,
        data: bytes | str,
        public_key_pem: str | None = None,
        key_id: str | None = None
    ) -> bool:
        """
        Verify Ed25519 signature against data.
        Accepts signature as raw bytes or hex string.
        Public key can be provided directly as PEM or resolved by key_id.
        """
        try:
            # Support both (signature, data) and (data, signature) order
            if isinstance(signature, (bytes, bytearray)) and len(signature) != 64:
                if (isinstance(data, str) and len(data) == 128) or (isinstance(data, (bytes, bytearray)) and len(data) == 64):
                    signature, data = data, signature

            sig_bytes: bytes = bytes.fromhex(signature) if isinstance(signature, str) else signature
            if len(sig_bytes) != 64:
                return False

            data_bytes: bytes = data.encode("utf-8") if isinstance(data, str) else data

            if public_key_pem:
                pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            elif key_id:
                registry = self._load_registry()
                key_info = registry.get("keys", {}).get(key_id)
                if not key_info:
                    # Try reading from disk pub file
                    pub_file = self.key_dir / f"{key_id}.pub.pem"
                    if pub_file.exists():
                        with open(pub_file, "rb") as f:
                            pub_key = serialization.load_pem_public_key(f.read())
                    else:
                        return False
                else:
                    pub_key = serialization.load_pem_public_key(key_info["public_key_pem"].encode("utf-8"))
            else:
                active_id = self.get_or_create_active_key()
                return self.verify_signature(sig_bytes, data_bytes, key_id=active_id)

            if isinstance(pub_key, ed25519.Ed25519PublicKey):
                pub_key.verify(sig_bytes, data_bytes)
                return True
            return False
        except Exception:
            return False

    def get_public_key_info(self, key_id: str | None = None) -> dict[str, Any]:
        """Retrieve public metadata for given key or active key (safe for API exposure)."""
        target_id = key_id or self.get_or_create_active_key()
        registry = self._load_registry()
        key_data = registry.get("keys", {}).get(target_id)
        if not key_data:
            pub_file = self.key_dir / f"{target_id}.pub.pem"
            if pub_file.exists():
                with open(pub_file, "rb") as f:
                    pem_str = f.read().decode("utf-8")
                pub_key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
                raw_hex = pub_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()  # type: ignore
                return {
                    "key_id": target_id,
                    "public_key_hex": raw_hex,
                    "public_key_pem": pem_str,
                    "algorithm": "Ed25519",
                    "status": "LOADED_FROM_DISK"
                }
            raise KeyError(f"Public key for {target_id} not found.")

        return {
            "key_id": key_data["key_id"],
            "alias": key_data.get("alias", ""),
            "created_at": key_data.get("created_at"),
            "public_key_hex": key_data["public_key_hex"],
            "public_key_pem": key_data["public_key_pem"],
            "algorithm": "Ed25519",
            "status": key_data.get("status", "ACTIVE")
        }

    def list_public_keys(self) -> list[dict[str, Any]]:
        """List all public keys in registry (audit safe)."""
        self.get_or_create_active_key()
        registry = self._load_registry()
        active = registry.get("active_key_id")
        result = []
        for kid, kdata in registry.get("keys", {}).items():
            result.append({
                "key_id": kid,
                "alias": kdata.get("alias", ""),
                "created_at": kdata.get("created_at"),
                "public_key_hex": kdata.get("public_key_hex"),
                "is_active": (kid == active),
                "status": kdata.get("status", "ACTIVE")
            })
        return result


# Global singleton instance
key_manager = JockyKeyManager()
