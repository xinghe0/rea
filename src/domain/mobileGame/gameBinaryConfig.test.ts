import { expect, it } from "vitest";
import { encode } from "@msgpack/msgpack";
import { decodeGameConfig } from "./gameBinaryConfig.js";

it("preserves null, false, all Pack.py top-level rows and wide signed values", () => {
  expect(decodeGameConfig(Buffer.from("null"))).toMatchObject({
    ok: true,
    value: [{ protocol: "JSON", values: [null] }],
  });
  expect(decodeGameConfig(Buffer.from("false"))).toMatchObject({
    ok: true,
    value: [{ protocol: "JSON", values: [false] }],
  });
  const bytes = Buffer.from([
    151, 2, 156, 154, 138, 255, 255, 255, 255, 255, 255, 255, 127,
  ]);
  const result = decodeGameConfig(bytes);
  expect(result.ok).toBe(true);
  if (result.ok)
    expect(
      result.value.find((candidate) => candidate.protocol === "Pack.py")
        ?.values,
    ).toEqual([[null, false], "9223372036854775807"]);
});
it("preserves duplicate/nonstring Pack.py dictionary keys as entry pairs", () => {
  const result = decodeGameConfig(Buffer.from([147, 2, 1, 2, 1, 3]));
  expect(result.ok).toBe(true);
  if (result.ok)
    expect(
      result.value.find((candidate) => candidate.protocol === "Pack.py")
        ?.values,
    ).toEqual([
      {
        entries: [
          [1, 2],
          [1, 3],
        ],
      },
    ]);
});
it("rejects a truncated Pack.py string and admits complete MessagePack", () => {
  const malformed = decodeGameConfig(Buffer.from([145, 5, 65]));
  if (malformed.ok)
    expect(
      malformed.value.some((candidate) => candidate.protocol === "Pack.py"),
    ).toBe(false);
  const result = decodeGameConfig(
    Buffer.from(encode({ enabled: false, count: 300 })),
  );
  expect(result.ok).toBe(true);
  if (result.ok)
    expect(result.value).toContainEqual({
      protocol: "MessagePack",
      values: [{ enabled: false, count: 300 }],
      consumed_bytes: encode({ enabled: false, count: 300 }).length,
    });
});
