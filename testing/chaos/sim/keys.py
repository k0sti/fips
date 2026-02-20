"""Key derivation wrapper, reusing logic from scripts/derive-keys.py."""

import importlib.util
import os

# Import derive() from scripts/derive-keys.py
_SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")
_DERIVE_KEYS_PATH = os.path.join(_SCRIPTS_DIR, "derive-keys.py")

_spec = importlib.util.spec_from_file_location("derive_keys", _DERIVE_KEYS_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

derive = _mod.derive  # derive(mesh_name, node_name) -> (nsec_hex, npub_bech32)
