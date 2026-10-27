import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from proto_wire_decode import decode_hex, decode_message, read_varint


class ProtoDecodeTests(unittest.TestCase):
    def test_decodes_varint_and_string(self):
        result = decode_message(bytes.fromhex("08960112026869"))
        self.assertTrue(result.complete)
        self.assertEqual(result.fields[0]["value"], 150)
        self.assertEqual(result.fields[1]["value"], "hi")

    def test_rejects_truncated_length_delimited_field(self):
        result = decode_message(bytes.fromhex("12056869"))
        self.assertFalse(result.complete)
        self.assertIn("exceeds remaining", result.error)

    def test_rejects_overflowing_varint(self):
        with self.assertRaises(ValueError):
            read_varint(b"\xff" * 10, 0)

    def test_detects_unique_big_endian_length_frame(self):
        body = bytes.fromhex("0801")
        framed = len(b"\x07" + body).to_bytes(2, "big") + b"\x07" + body
        result = decode_hex(framed.hex())
        self.assertEqual(result["message_id"], 7)
        self.assertTrue(result["decode"]["complete"])

    def test_invalid_wire_type_is_incomplete(self):
        result = decode_message(bytes.fromhex("0b"))
        self.assertFalse(result.complete)
        self.assertIn("unsupported wire type", result.error)


if __name__ == "__main__":
    unittest.main()
