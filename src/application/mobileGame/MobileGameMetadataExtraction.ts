import { open } from "node:fs/promises";
import { createHash } from "node:crypto";
import { ZipArtifactReader } from "../../artifacts/ZipArtifactReader.js";

/** Extract one exact APK member; output is selected by the case owner, never by the member path. */
export const extractGameMetadata = async (
  apk: string,
  member: string,
  output: string,
  signal?: AbortSignal,
): Promise<{ path: string; member: string; sha256: string; bytes: number }> => {
  const reader = new ZipArtifactReader(apk, "apk");
  try {
    const matches = [];
    for await (const entry of reader.entries(signal))
      if (entry.path === member && entry.kind === "file") matches.push(entry);
    if (matches.length !== 1)
      throw new Error(
        `Expected one metadata entry, observed ${matches.length}: ${member}`,
      );
    const entry = matches[0]!;
    const source = await reader.open(entry, signal);
    const target = await open(output, "wx", 0o600).catch((cause: unknown) => {
      source.destroy();
      throw cause;
    });
    const hash = createHash("sha256");
    let bytes = 0;
    try {
      for await (const chunk of source) {
        signal?.throwIfAborted();
        const buffer = Buffer.from(chunk);
        hash.update(buffer);
        let written = 0;
        while (written < buffer.length) {
          const result = await target.write(
            buffer,
            written,
            buffer.length - written,
          );
          if (result.bytesWritten === 0)
            throw new Error("Metadata output write made no progress");
          written += result.bytesWritten;
        }
        bytes += buffer.length;
      }
      await target.sync();
    } finally {
      source.destroy();
      await target.close();
    }
    return { path: output, member, sha256: hash.digest("hex"), bytes };
  } finally {
    await reader.close();
  }
};
