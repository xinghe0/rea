import { ZipArtifactReader } from "../../artifacts/ZipArtifactReader.js";
import type { ArtifactEntry } from "../../artifacts/ArtifactReader.js";
import { createHash, randomUUID } from "node:crypto";
import {
  runOwnedCommand,
  OwnedCommandFailure,
} from "../../process/OwnedCommand.js";
import type { ProviderProcessSnapshot } from "../../process/ProviderProcess.js";

export interface ApkEntry {
  readonly path: string;
  readonly size: number | null;
}
export interface ResourceFact {
  readonly path: string;
  readonly extension: string;
  readonly type: string;
  readonly encrypted: boolean | null;
  readonly note: string;
}
export interface SensitiveHit {
  readonly value: string;
  readonly path: string;
  readonly type: string;
  readonly offset: number;
  readonly length: number;
  readonly value_sha256_prefix: string;
}
export interface DeviceBaseline {
  readonly serial: string | null;
  readonly state: string;
  readonly model: string | null;
  readonly android_version: string | null;
  readonly sdk: string | null;
  readonly root: boolean | null;
  readonly limitations: readonly string[];
}

const MAGIC: ReadonlyArray<readonly [string, string]> = [
  ["89504e470d0a1a0a", "image_png"],
  ["ffd8ff", "image_jpg"],
  ["4f676753", "audio_ogg"],
  ["556e6974794653", "assetbundle"],
  ["af1bb1fa", "il2cpp_metadata"],
  ["7f454c46", "native_lib"],
  ["4d5a9000", "dotnet_pe"],
  ["414b504b", "wwise_akpk"],
  ["03000800", "android_axml"],
];

const run = async (
  command: string,
  args: readonly string[],
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<ProviderProcessSnapshot> => {
  try {
    return await runOwnedCommand(
      {
        command,
        arguments: [...args],
        runId: `rea-mobile-static-${randomUUID()}`,
        hostEnvironment: process.env,
        ...(signal === undefined ? {} : { signal }),
      },
      { timeoutMs, diagnosticBytes: 64 * 1024 * 1024 },
    );
  } catch (cause: unknown) {
    if (cause instanceof OwnedCommandFailure)
      throw new Error(`${command} failed: ${cause.reason}`, { cause });
    throw cause;
  }
};

/** Read ZIP central-directory facts without extracting unbounded entries. */
export const listApkEntries = async (
  apk: string,
  signal?: AbortSignal,
): Promise<readonly ApkEntry[]> => {
  const reader = new ZipArtifactReader(apk, "apk");
  try {
    const entries: ApkEntry[] = [];
    for await (const entry of reader.entries(signal))
      if (entry.kind === "file")
        entries.push({ path: entry.path, size: entry.declaredSize });
    return entries;
  } finally {
    await reader.close();
  }
};
const readPrefix = async (
  reader: ZipArtifactReader,
  entry: ArtifactEntry,
  limit: number,
  signal?: AbortSignal,
): Promise<Buffer> => {
  const stream = await reader.open(entry, signal);
  const chunks: Buffer[] = [];
  let length = 0;
  try {
    for await (const chunk of stream) {
      signal?.throwIfAborted();
      const bytes = Buffer.from(chunk);
      const kept = bytes.subarray(0, limit - length);
      chunks.push(kept);
      length += kept.length;
      if (length >= limit) break;
    }
    return Buffer.concat(chunks, length);
  } finally {
    stream.destroy();
  }
};

export interface ManifestFact {
  readonly available: boolean;
  readonly package_name: string | null;
  readonly version_code: string | null;
  readonly version_name: string | null;
  readonly min_sdk: string | null;
  readonly target_sdk: string | null;
  readonly permissions: readonly string[];
  readonly exported_candidates: readonly string[] | null;
  readonly warning?: string;
}

/** Parse aapt's text boundary once; absence remains unknown instead of false. */
export const inspectApkManifest = async (
  apk: string,
  signal?: AbortSignal,
): Promise<ManifestFact> => {
  try {
    const snapshot = await run(
      "aapt",
      ["dump", "badging", apk],
      30_000,
      signal,
    );
    if (snapshot.exitCode !== 0)
      return {
        available: false,
        package_name: null,
        version_code: null,
        version_name: null,
        min_sdk: null,
        target_sdk: null,
        permissions: [],
        exported_candidates: null,
        warning: snapshot.stderr.text || "aapt returned a non-zero exit",
      };
    const text = snapshot.stdout.text;
    const packageMatch =
      /package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'/u.exec(
        text,
      );
    const value = (pattern: RegExp): string | null =>
      pattern.exec(text)?.[1] ?? null;
    return {
      available: true,
      package_name: packageMatch?.[1] ?? null,
      version_code: packageMatch?.[2] ?? null,
      version_name: packageMatch?.[3] ?? null,
      min_sdk: value(/sdkVersion:'([^']+)'/u),
      target_sdk: value(/targetSdkVersion:'([^']+)'/u),
      permissions: [
        ...new Set(
          [...text.matchAll(/uses-permission(?:-sdk-\d+)?: name='([^']+)'/gu)]
            .map((match) => match[1])
            .filter(
              (permission): permission is string => permission !== undefined,
            ),
        ),
      ],
      exported_candidates: null,
    };
  } catch (cause: unknown) {
    signal?.throwIfAborted();
    return {
      available: false,
      package_name: null,
      version_code: null,
      version_name: null,
      min_sdk: null,
      target_sdk: null,
      permissions: [],
      exported_candidates: null,
      warning: cause instanceof Error ? cause.message : "aapt unavailable",
    };
  }
};

const classify = (entry: ApkEntry, head: string): ResourceFact => {
  const extension = entry.path.includes(".")
    ? entry.path.slice(entry.path.lastIndexOf(".")).toLowerCase()
    : "";
  const magic = MAGIC.find(([prefix]) => head.startsWith(prefix));
  if (magic !== undefined)
    return {
      path: entry.path,
      extension,
      type: magic[1],
      encrypted: null,
      note: "recognized header; body integrity and encryption remain unverified",
    };
  if (
    extension === ".json" ||
    extension === ".xml" ||
    extension === ".txt" ||
    extension === ".cfg" ||
    extension === ".ini"
  )
    return {
      path: entry.path,
      extension,
      type: "config_candidate",
      encrypted: null,
      note: "content validation required",
    };
  if (
    extension === ".unity3d" ||
    extension === ".bytes" ||
    entry.path.toLowerCase().includes("assetbundle")
  )
    return {
      path: entry.path,
      extension,
      type: "assetbundle_candidate",
      encrypted: null,
      note: "Unity parser validation required",
    };
  return {
    path: entry.path,
    extension,
    type: "unknown",
    encrypted: null,
    note: "format not recognized from bounded header",
  };
};

export const scanApkResources = async (
  apk: string,
  _entries: readonly ApkEntry[],
  signal?: AbortSignal,
): Promise<readonly ResourceFact[]> => {
  const reader = new ZipArtifactReader(apk, "apk");
  const facts: ResourceFact[] = [];
  try {
    for await (const entry of reader.entries(signal)) {
      if (entry.kind !== "file") continue;
      const head = await readPrefix(reader, entry, 64, signal);
      facts.push(
        classify(
          { path: entry.path, size: entry.declaredSize },
          head.toString("hex"),
        ),
      );
    }
    return facts;
  } finally {
    await reader.close();
  }
};

const SENSITIVE_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu],
  ["private-key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gu],
  ["cloud-access-key", /\b(?:AKIA|ASIA|AKID|LTAI)[A-Z0-9]{12,}\b/gu],
  [
    "email",
    /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}\b/gu,
  ],
  ["phone", /(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)/gu],
  [
    "key-value",
    /(?:token|secret|password|passwd|authorization|api[_-]?key)\s*["']?\s*[:=]\s*["']?([^\s"'&,;}{]{8,256})/giu,
  ],
];

const textCandidate = (entry: ApkEntry): boolean => {
  const lower = entry.path.toLowerCase();
  return (
    [
      ".json",
      ".xml",
      ".txt",
      ".cfg",
      ".ini",
      ".properties",
      ".js",
      ".lua",
      ".csv",
      ".config",
    ].some((suffix) => lower.endsWith(suffix)) || !lower.includes(".")
  );
};

/** Preserve bounded pattern candidates as source facts; matches do not establish secrecy. */
export const scanApkSensitiveStrings = async (
  apk: string,
  _entries: readonly ApkEntry[],
  signal?: AbortSignal,
): Promise<readonly SensitiveHit[]> => {
  const hits: SensitiveHit[] = [];
  const reader = new ZipArtifactReader(apk, "apk");
  try {
    for await (const entry of reader.entries(signal)) {
      if (
        entry.kind !== "file" ||
        !textCandidate({ path: entry.path, size: entry.declaredSize })
      )
        continue;
      const text = (await readPrefix(reader, entry, 524288, signal)).toString(
        "utf8",
      );
      for (const [type, pattern] of SENSITIVE_PATTERNS) {
        pattern.lastIndex = 0;
        for (const match of text.matchAll(pattern)) {
          const value = match[1] ?? match[0];
          hits.push({
            path: entry.path,
            type,
            value,
            offset: match.index ?? 0,
            length: value.length,
            value_sha256_prefix: createHash("sha256")
              .update(value)
              .digest("hex")
              .slice(0, 16),
          });
        }
      }
    }
    return hits;
  } finally {
    await reader.close();
  }
};

/** Passive ADB baseline. It never installs, starts, stops, or writes device state. */
export const collectDeviceBaseline = async (
  signal?: AbortSignal,
  selectedSerial?: string,
): Promise<DeviceBaseline> => {
  if (selectedSerial === undefined)
    return {
      serial: null,
      state: "not-selected",
      model: null,
      android_version: null,
      sdk: null,
      root: null,
      limitations: ["Select a serial to collect device evidence."],
    };
  try {
    const devices = await runOwnedCommand(
      {
        command: "adb",
        arguments: ["devices"],
        runId: `rea-mobile-device-${randomUUID()}`,
        hostEnvironment: process.env,
        ...(signal === undefined ? {} : { signal }),
      },
      { timeoutMs: 15_000, diagnosticBytes: 64 * 1024 },
    );
    const row = devices.stdout.text
      .split(/\r?\n/u)
      .map((line) => /^([^\s]+)\s+(device)$/u.exec(line))
      .find((match) => match?.[1] === selectedSerial);
    if (row?.[1] === undefined)
      return {
        serial: null,
        state: "not-connected",
        model: null,
        android_version: null,
        sdk: null,
        root: null,
        limitations: ["No authorized adb device was observed."],
      };
    const serial = row[1];
    const props = await runOwnedCommand(
      {
        command: "adb",
        arguments: ["-s", serial, "shell", "getprop"],
        runId: `rea-mobile-device-${randomUUID()}`,
        hostEnvironment: process.env,
        ...(signal === undefined ? {} : { signal }),
      },
      { timeoutMs: 20_000, diagnosticBytes: 128 * 1024 },
    );
    const value = (key: string): string | null =>
      new RegExp(`\\[${key.replaceAll(".", "\\.")}\\]: \\[(.*?)\\]`, "u").exec(
        props.stdout.text,
      )?.[1] ?? null;
    const rootProbe = await runOwnedCommand(
      {
        command: "adb",
        arguments: ["-s", serial, "shell", "sh", "-c", "id"],
        runId: `rea-mobile-device-${randomUUID()}`,
        hostEnvironment: process.env,
        ...(signal === undefined ? {} : { signal }),
      },
      {
        timeoutMs: 10_000,
        diagnosticBytes: 16 * 1024,
        acceptNonZeroExit: true,
      },
    );
    return {
      serial,
      state: "device",
      model: value("ro.product.model"),
      android_version: value("ro.build.version.release"),
      sdk: value("ro.build.version.sdk"),
      root: /uid=0\b/u.test(rootProbe.stdout.text),
      limitations: [
        "Root status is based only on the observed adb shell identity.",
      ],
    };
  } catch (cause: unknown) {
    signal?.throwIfAborted();
    return {
      serial: null,
      state: "unavailable",
      model: null,
      android_version: null,
      sdk: null,
      root: null,
      limitations: [cause instanceof Error ? cause.message : "adb unavailable"],
    };
  }
};
