import { decode } from "@msgpack/msgpack";
import { jsonValueSchema, type JsonValue } from "../jsonValue.js";
import { err, ok, type Result } from "../result.js";

/** Pack.py has no magic: keep successful interpretations as candidates, never guess one. */
class PackReader {
  offset = 0;
  private nodes = 0;
  constructor(private readonly bytes: Buffer) {}
  private take(size: number): Buffer {
    if (
      !Number.isSafeInteger(size) ||
      size < 0 ||
      size > this.bytes.length - this.offset
    )
      throw new Error(`Truncated Pack.py value at ${this.offset}`);
    const value = this.bytes.subarray(this.offset, this.offset + size);
    this.offset += size;
    return value;
  }
  private unsigned(size: number): number {
    return this.take(size).readUIntLE(0, size);
  }
  private signed(size: number): number | string {
    const data = this.take(size);
    if (size !== 8) return data.readIntLE(0, size);
    const value = data.readBigInt64LE();
    return value >= BigInt(Number.MIN_SAFE_INTEGER) &&
      value <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(value)
      : value.toString();
  }
  private text(size: number): string {
    return new TextDecoder("utf-8", { fatal: true }).decode(this.take(size));
  }
  value(depth = 0): JsonValue {
    if (depth > 64 || ++this.nodes > 1_000_000)
      throw new Error("Pack.py nesting/node budget exceeded");
    const flag = this.take(1).readInt8();
    if (flag > -100) return flag;
    if (flag === -100) return null;
    if (flag === -101 || flag === -102) return flag === -101;
    if (flag <= -115 && flag >= -118)
      return this.signed([1, 2, 4, 8][-flag - 115]!);
    if (flag <= -111 && flag >= -113)
      return this.text(this.unsigned([1, 2, 4][-flag - 111]!));
    if (flag === -114) return { datetime: this.value(depth + 1) };
    if (flag <= -103 && flag >= -110) {
      const count = this.unsigned(-flag % 2 === 1 ? 1 : 2);
      if (count > this.bytes.length - this.offset)
        throw new Error("Pack.py collection exceeds remaining bytes");
      if (flag >= -108)
        return Array.from({ length: count }, () => this.value(depth + 1));
      // Entry pairs retain non-string and duplicate keys without display coercion.
      return {
        entries: Array.from({ length: count }, () => [
          this.value(depth + 1),
          this.value(depth + 1),
        ]),
      };
    }
    if (flag === -119 || flag === -120) {
      const classFlag = this.take(1).readInt8();
      const name = this.text(
        classFlag === -111
          ? this.unsigned(1)
          : classFlag === -112
            ? this.unsigned(2)
            : classFlag >= 0
              ? classFlag
              : -1,
      );
      const countFlag = this.take(1).readInt8();
      const count =
        countFlag === -100 ? 0 : countFlag >= 0 ? countFlag : this.unsigned(1);
      const entries: JsonValue[] = [];
      for (let index = 0; index < count; index++)
        entries.push([this.value(depth + 1), this.value(depth + 1)]);
      return {
        class_name: name,
        representation: flag === -119 ? "object" : "binary",
        entries,
      };
    }
    throw new Error(`Unknown Pack.py flag ${flag}`);
  }
}

export interface GameConfigInterpretation {
  protocol: string;
  values: JsonValue[];
  consumed_bytes: number;
}
/** All input bytes must be consumed; null and false are legitimate successful values. */
export const decodeGameConfig = (
  bytes: Buffer,
): Result<readonly GameConfigInterpretation[], string> => {
  if (bytes.length > 16 * 1024 * 1024)
    return err("Configuration exceeds the 16 MiB decoder input budget");
  const candidates: GameConfigInterpretation[] = [];
  try {
    const value = jsonValueSchema.parse(
      JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
    );
    candidates.push({
      protocol: "JSON",
      values: [value],
      consumed_bytes: bytes.length,
    });
    return ok(candidates);
  } catch {
    /* Other wire grammars may apply. */
  }
  try {
    const value = jsonValueSchema.parse(
      decode(bytes, {
        useBigInt64: true,
        maxStrLength: 16 * 1024 * 1024,
        maxBinLength: 16 * 1024 * 1024,
        maxArrayLength: 1_000_000,
        maxMapLength: 1_000_000,
        maxExtLength: 16 * 1024 * 1024,
        mapKeyConverter: (key) => {
          if (typeof key !== "string")
            throw new Error(
              "Non-string MessagePack key needs a lossless mapping",
            );
          return key;
        },
      }),
    );
    candidates.push({
      protocol: "MessagePack",
      values: [value],
      consumed_bytes: bytes.length,
    });
  } catch {
    /* Unsupported values are not silently coerced. */
  }
  try {
    const reader = new PackReader(bytes);
    const values: JsonValue[] = [];
    while (reader.offset < bytes.length) values.push(reader.value());
    if (values.length > 0)
      candidates.push({
        protocol: "Pack.py",
        values,
        consumed_bytes: reader.offset,
      });
  } catch {
    /* A prefix parse never establishes complete decoding. */
  }
  return candidates.length === 0
    ? err("No complete supported JSON, MessagePack or Pack.py interpretation")
    : ok(candidates);
};
