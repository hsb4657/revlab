from __future__ import annotations

import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.services import unity
from app.services.unity import detector, il2cpp, split_metadata


FIXTURE = ROOT / "samples" / "unity_sample"
METADATA = FIXTURE / "Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
GAMEASSEMBLY = FIXTURE / "GameAssembly.dll"
MANAGED_ASSEMBLY = FIXTURE / "Data" / "Managed" / "Assembly-CSharp.dll"


@unittest.skipUnless(METADATA.is_file() and GAMEASSEMBLY.is_file(), "Unity fixture is missing")
class UnityServiceTests(unittest.TestCase):
    def test_il2cpp_detection_has_explainable_evidence(self):
        result = detector.detect_unity(str(FIXTURE))
        self.assertEqual(result["build_type"], "IL2CPP")
        evidence = result["build_evidence"]
        self.assertEqual(evidence["selected"], "IL2CPP")
        self.assertEqual(evidence["confidence"], "high")
        self.assertIn("GameAssembly.dll", evidence["il2cpp"])
        self.assertIn("global-metadata.dat", evidence["il2cpp"])

    def test_plain_metadata_is_verified_and_builtin_diagnostics_are_complete(self):
        inspection = il2cpp.check_metadata_encrypted(str(METADATA))
        self.assertEqual(inspection["status"], "plain")
        self.assertTrue(inspection["parseable"])
        self.assertFalse(inspection["encrypted"])

        with tempfile.TemporaryDirectory() as temp:
            # The tiny fixture PE is intentionally not a real IL2CPP binary,
            # so it cannot be an official Il2CppDumper end-to-end fixture.
            # Exercise the built-in metadata diagnostics here; production
            # dump_sdk remains gated on official DummyDll output.
            result = il2cpp._dump_sdk_builtin(str(METADATA), str(GAMEASSEMBLY), temp)
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["delivery_complete"], result)
            self.assertEqual(result["status"], "completed")
            for key in ("dump_cs", "script_json", "sdk_json", "manifest", "dll", "metadata"):
                self.assertTrue(Path(result[key]).is_file(), key)
            self.assertTrue(result["cpp_headers"])
            self.assertTrue(all(Path(path).is_file() for path in result["cpp_headers"]))

            manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], "revlab.unity.sdk-manifest/v1")
            self.assertTrue(manifest["delivery_complete"])
            kinds = {artifact["kind"] for artifact in manifest["artifacts"]}
            self.assertTrue({"dump_cs", "script_json", "sdk_json", "cpp_header", "metadata", "gameassembly"} <= kinds)
            self.assertFalse(manifest["missing_required"])

    def test_single_byte_xor_metadata_is_only_marked_decrypted_after_validation(self):
        source = METADATA.read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            encrypted = root / "global-metadata.dat"
            encrypted.write_bytes(bytes(byte ^ 0xA7 for byte in source))
            inspected = il2cpp.check_metadata_encrypted(str(encrypted))
            self.assertEqual(inspected["status"], "encrypted_or_obfuscated")
            self.assertTrue(inspected["encrypted"])

            restored = root / "restored.dat"
            result = il2cpp.decrypt_metadata(str(encrypted), out_path=str(restored))
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["status"], "decrypted")
            self.assertTrue(result["verified"])
            self.assertTrue(result["decrypted"])
            self.assertTrue(restored.is_file())
            self.assertTrue(il2cpp.parse_metadata(str(restored))["valid"])

    def test_header_repair_is_not_reported_as_decryption_or_sdk_ready(self):
        """A damaged magic can be structurally repaired, but is not decryption."""
        source = METADATA.read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            damaged = root / "global-metadata.dat"
            damaged.write_bytes(b"bad" + source[3:])

            inspected = il2cpp.check_metadata_encrypted(str(damaged))
            self.assertNotEqual(inspected["status"], "plain")

            repaired = root / "repaired.dat"
            result = il2cpp.decrypt_metadata(str(damaged), out_path=str(repaired))
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["status"], "header_repaired")
            self.assertTrue(result["verified"])
            self.assertTrue(result["repaired"])
            self.assertFalse(result["decrypted"])
            self.assertTrue(il2cpp.parse_metadata(str(repaired))["valid"])

            # The workflow keeps the provenance flag and must block SDK export
            # even though the repaired copy is structurally parseable on disk.
            pipeline = {
                "buildtype": {"build_type": "IL2CPP"},
                "decrypt": {
                    "status": "header_repaired",
                    "verified": True,
                    "decrypted": False,
                    "repaired": True,
                    "metadata": str(damaged),
                    "decrypted_path": str(repaired),
                    "usable_metadata_path": "",
                },
                "assembly": {"gameassembly_path": str(GAMEASSEMBLY)},
            }
            sdk = unity.execute_stage("sdk", {"params": {}, "target_path": str(root)}, pipeline)
            self.assertFalse(sdk["ok"])
            self.assertEqual(sdk["status"], "blocked_by_metadata")
            self.assertFalse(sdk["delivery_complete"])

    def test_standard_byte_length_table_counts_are_normalized(self):
        """Official IL2CPP headers use byte lengths for record-table counts."""
        data = bytearray(METADATA.read_bytes())
        struct.pack_into("<I", data, 0x34, 4 * 32)   # methods, v25+
        struct.pack_into("<I", data, 0x64, 3 * 12)   # fields
        struct.pack_into("<I", data, 0xA4, 3 * 76)   # type definitions, v25+
        struct.pack_into("<I", data, 0xAC, 1 * 40)   # images, v27+
        with tempfile.TemporaryDirectory() as temp:
            metadata = Path(temp) / "global-metadata.dat"
            metadata.write_bytes(data)
            parsed = il2cpp.parse_metadata(str(metadata))
            self.assertTrue(parsed["valid"], parsed)
            self.assertEqual(parsed["table_count_semantics"], "byte_length")
            self.assertEqual(parsed["type_count"], 3)
            self.assertEqual(parsed["method_count"], 4)
            self.assertEqual(parsed["field_count"], 3)

    def test_corrupt_metadata_is_not_reported_as_decrypted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            corrupt = root / "global-metadata.dat"
            corrupt.write_bytes(b"\x00" * 1024)
            inspected = il2cpp.check_metadata_encrypted(str(corrupt))
            self.assertNotEqual(inspected["status"], "plain")
            restored = root / "restored.dat"
            result = il2cpp.decrypt_metadata(str(corrupt), out_path=str(restored))
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "decryption_failed")
            self.assertFalse(result["verified"])
            self.assertFalse(result["decrypted"])
            self.assertEqual(result["decrypted_path"], "")
            self.assertFalse(restored.exists())

    def test_unencrypted_corrupt_metadata_skips_workflow_decryption(self):
        """A malformed file is reported, not sent through a decoder by default."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            metadata = root / "Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
            metadata.parent.mkdir(parents=True)
            metadata.write_bytes(b"\x00" * 1024)
            (root / "GameAssembly.dll").write_bytes(b"MZ" + b"\x00" * 128)
            ctx = {"params": {}, "target_path": str(root)}
            result = {}
            for stage in ("scan", "version", "buildtype", "assembly", "decrypt"):
                result[stage] = unity.execute_stage(stage, ctx, result)
            decrypt = result["decrypt"]
            self.assertEqual(result["buildtype"]["build_type"], "IL2CPP")
            self.assertEqual(decrypt["status"], "corrupt_or_unknown")
            self.assertFalse(decrypt["encrypted"])
            self.assertFalse(decrypt["decryption_required"])
            self.assertFalse(decrypt["decryption_attempted"])
            self.assertEqual(decrypt["decryption_status"], "not_required")

    def test_renamed_high_entropy_metadata_candidates_require_runtime_binding(self):
        """A hashed high-entropy blob is evidence, never a completed decrypt."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / "Game_Data" / "il2cpp_data"
            data_dir.mkdir(parents=True)
            candidate = data_dir / "0123456789abcdef0123456789abcdef"
            candidate.write_bytes(bytes(range(256)) * 32)
            (root / "GameAssembly.dll").write_bytes(b"MZ" + b"\x00" * 128 + b"il2cpp_init")
            (root / "UnityPlayer.dll").write_bytes(b"MZ" + b"\x00" * 128)
            (root / "Game_Data" / "globalgamemanagers").write_bytes(b"UnityFS")

            ctx = {"params": {}, "target_path": str(root)}
            result = {}
            for stage in ("scan", "version", "buildtype", "assembly", "decrypt", "sdk"):
                result[stage] = unity.execute_stage(stage, ctx, result)

            candidates = result["scan"]["detect"]["metadata_candidates"]
            self.assertEqual(candidates["status"], "metadata_renamed_or_obfuscated_candidate")
            self.assertEqual(candidates["candidate_count"], 1)
            self.assertFalse(candidates["candidates"][0]["magic_found"])
            decrypt = result["decrypt"]
            self.assertEqual(decrypt["status"], "metadata_renamed_or_obfuscated_candidate")
            self.assertFalse(decrypt["encrypted"])
            self.assertTrue(decrypt["encryption_suspected"])
            self.assertFalse(decrypt["decryption_required"])
            self.assertFalse(decrypt["decryption_attempted"])
            self.assertTrue(decrypt["runtime_validation"]["required"])
            self.assertEqual(result["sdk"]["status"], "blocked_by_metadata")

    def test_mono_path_is_explicitly_not_applicable_for_il2cpp_sdk(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            managed = root / "Data" / "Managed"
            managed.mkdir(parents=True)
            shutil.copy2(MANAGED_ASSEMBLY, managed / "Assembly-CSharp.dll")
            ctx = {"params": {}, "target_path": str(root)}
            result = {}
            for stage in ("scan", "version", "buildtype", "assembly", "decrypt", "sdk"):
                result[stage] = unity.execute_stage(stage, ctx, result)
            self.assertEqual(result["buildtype"]["build_type"], "Mono")
            self.assertEqual(result["decrypt"]["status"], "not_applicable")
            self.assertEqual(result["sdk"]["status"], "not_applicable")
            self.assertFalse(result["sdk"]["delivery_complete"])

    def test_official_dumper_receives_verified_registration_addresses(self):
        with tempfile.TemporaryDirectory() as temp, \
                unittest.mock.patch.object(il2cpp.subprocess, "run") as run:
            run.return_value.returncode = 1
            run.return_value.stdout = ""
            run.return_value.stderr = "failed"
            registration = {
                "found": True,
                "code_registration": 0x185FA8ED0,
                "metadata_registration": 0x185FA8F60,
            }
            il2cpp._official_il2cpp_dumper(
                str(METADATA), str(GAMEASSEMBLY), Path(temp), registration
            )
            command = next(
                call.args[0] for call in run.call_args_list
                if call.args and call.args[0] and
                str(call.args[0][0]).lower().endswith("il2cppdumper.exe")
            )
            self.assertEqual(command[-2:], ["185fa8ed0", "185fa8f60"])


if __name__ == "__main__":
    unittest.main()
