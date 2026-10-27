import { it, expect } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ZipWriter, Uint8ArrayWriter, Uint8ArrayReader } from "@zip.js/zip.js";
import {
  listApkEntries,
  scanApkResources,
  scanApkSensitiveStrings,
} from "./MobileGameStaticAnalysis.js";

it("preserves ZIP names, classifies headers without claiming decrypted bodies and scans candidate values", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-mobile-test-"));
  try {
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add(
      "assets/config with spaces.json",
      new Uint8ArrayReader(Buffer.from('{"token":"example-token-123456"}')),
    );
    await writer.add(
      "assets/image.png",
      new Uint8ArrayReader(Buffer.from("89504e470d0a1a0a00000000", "hex")),
    );
    const path = join(directory, "sample.apk");
    await writeFile(path, await writer.close());
    const entries = await listApkEntries(path);
    expect(entries[0]?.path).toBe("assets/config with spaces.json");
    expect(entries[0]?.size).toBeGreaterThan(0);
    const resources = await scanApkResources(path, entries);
    expect(
      resources.find((fact) => fact.type === "image_png")?.encrypted,
    ).toBeNull();
    const hits = await scanApkSensitiveStrings(path, entries);
    expect(hits.some((hit) => hit.type === "key-value")).toBe(true);
    expect(JSON.stringify(hits)).toContain("example-token-123456");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("extracts exactly one metadata member and refuses output overwrite", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-mobile-metadata-"));
  try {
    const { extractGameMetadata } =
      await import("./MobileGameMetadataExtraction.js");
    const writer = new ZipWriter(new Uint8ArrayWriter());
    const member = "assets/bin/Data/Managed/Metadata/global-metadata.dat";
    const bytes = Buffer.from("af1bb1fa18000000", "hex");
    await writer.add(member, new Uint8ArrayReader(bytes));
    const apk = join(directory, "fixture.apk");
    const output = join(directory, "metadata.dat");
    await writeFile(apk, await writer.close());
    const extracted = await extractGameMetadata(apk, member, output);
    expect(extracted.bytes).toBe(bytes.length);
    expect(extracted.sha256).toMatch(/^[a-f0-9]{64}$/u);
    await expect(extractGameMetadata(apk, member, output)).rejects.toThrow();
    const controller = new AbortController();
    controller.abort(new Error("test cancellation"));
    await expect(
      extractGameMetadata(
        apk,
        member,
        join(directory, "cancelled.dat"),
        controller.signal,
      ),
    ).rejects.toThrow();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
