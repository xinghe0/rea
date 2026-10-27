import { resolveAdbBinary } from "../adb/AdbConfiguration.js";
import type { AdbDeviceAnalysisService } from "../application/adb/AdbDeviceAnalysisService.js";
import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import {
  basename,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";
import { fileURLToPath } from "node:url";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import { decodeGameConfig } from "../domain/mobileGame/gameBinaryConfig.js";
import type { GameResourceInput } from "../domain/mobileGame/gameResourceInput.js";
import { runOwnedCommand } from "../process/OwnedCommand.js";
import type { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import { z } from "zod";

const unityResult = z.strictObject({
  status: z.enum(["completed", "partial", "suspect", "failed"]),
  objects: z.number().int().nonnegative(),
  exported: z.number().int().nonnegative(),
  failed: z.number().int().nonnegative(),
  skipped: z.number().int().nonnegative(),
  header_offset: z.number().int(),
  output_bytes: z.number().int().nonnegative(),
  failures: z.array(z.string()),
});
interface Source {
  name: string;
  origin: string;
  size: number | null;
  stream: () => Promise<NodeJS.ReadableStream & AsyncIterable<Buffer | string>>;
}
interface RecordFact {
  source: string;
  origin: string;
  status: string;
  bytes?: number;
  sha256?: string;
  artifact?: string;
  reason?: string;
  conversions?: Record<string, unknown>[];
}

/** Offline conversion owner. Input binaries are parsed by selected tools, never launched. */
export class GameResourceProvider {
  private readonly cleanup = new Set<ProviderProcessSupervisor>();
  async close(): Promise<void> {
    const failures: unknown[] = [];
    for (const owner of this.cleanup) {
      try {
        const result = await owner.stop();
        if (result.status !== "incomplete") this.cleanup.delete(owner);
        else failures.push(result.reason);
      } catch (cause) {
        failures.push(cause);
      }
    }
    if (failures.length > 0)
      throw new AggregateError(
        failures,
        `Resource converter cleanup remains pending: ${failures.map((failure) => String(failure)).join("; ")}`,
      );
  }
  private async command(command: string, args: string[], signal?: AbortSignal) {
    return runOwnedCommand(
      {
        command,
        arguments: args,
        runId: `rea-game-resource-${randomUUID()}`,
        hostEnvironment: process.env,
        ...(signal === undefined ? {} : { signal }),
      },
      {
        timeoutMs: 180_000,
        diagnosticBytes: 4 * 1024 * 1024,
        acceptNonZeroExit: true,
      },
      {
        ...(signal === undefined ? {} : { signal }),
        retainCleanup: (owner) => {
          this.cleanup.add(owner);
        },
      },
    );
  }
  async acquireDeviceResources(
    adb: AdbDeviceAnalysisService,
    serial: string,
    packageName: string,
    output: string,
    signal?: AbortSignal,
  ): Promise<{ roots: string[]; failed: number }> {
    if (
      !/^[^\x00\s"']+$/u.test(serial) ||
      !/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$/u.test(packageName)
    )
      throw new Error("Invalid device selection");
    await mkdir(output);
    const base = `/sdcard/Android/data/${packageName}/files`;
    const listing = await this.command(
      resolveAdbBinary(process.env).binary,
      ["-s", serial, "shell", "find", base, "-type", "f"],
      signal,
    );
    await writeFile(
      join(output, "inventory.json"),
      JSON.stringify(
        {
          serial,
          package: packageName,
          base,
          exit_code: listing.exitCode,
          stdout: listing.stdout.text,
          stderr: listing.stderr.text,
        },
        null,
        2,
      ),
      { flag: "wx" },
    );
    if (listing.exitCode !== 0) return { roots: [], failed: 1 };
    const roots: string[] = [];
    let failed = 0;
    for (const [index, path] of listing.stdout.text
      .replaceAll("\r\n", "\n")
      .split("\n")
      .filter((path) => path.length > 0)
      .entries()) {
      signal?.throwIfAborted();
      // A line-oriented adb listing cannot establish filenames containing line breaks.
      if (!path.startsWith(`${base}/`) || path.includes("\0")) {
        failed++;
        continue;
      }
      const destination = join(output, String(index).padStart(8, "0"));
      await mkdir(destination);
      const pulled = await adb.execute(
        "pull_adb_file",
        { serial, device_path: path, output_directory: destination },
        signal === undefined ? {} : { signal },
      );
      await writeFile(
        join(output, `${index}.evidence.json`),
        JSON.stringify(
          pulled.ok
            ? pulled.value
            : { status: "failed", reason: pulled.error.message },
          null,
          2,
        ),
        { flag: "wx" },
      );
      if (pulled.ok) roots.push(destination);
      else failed++;
    }
    return { roots, failed };
  }
  async convert(
    input: GameResourceInput,
    signal?: AbortSignal,
  ): Promise<{
    output_directory: string;
    manifest: string;
    examined: number;
    completed: number;
    failed: number;
    limited: number;
  }> {
    signal?.throwIfAborted();
    const output = resolve(input.output_directory);
    for (const root of input.options.roots) {
      const path = relative(resolve(root), output);
      if (
        path === "" ||
        (!isAbsolute(path) &&
          path !== ".." &&
          !path.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`))
      )
        throw new Error("Resource output must be outside the input tree");
    }
    await mkdir(output); // exclusive case ownership: never overwrite an existing output tree
    const facts: RecordFact[] = [];
    let total = 0;
    const persist = () =>
      writeFile(
        join(output, "manifest.json"),
        JSON.stringify(
          {
            schema_version: 1,
            options: input.options,
            total_input_bytes: total,
            coverage:
              "per-file outcomes; source trees are not atomic snapshots",
            files: facts,
          },
          null,
          2,
        ),
      );
    const processSource = async (source: Source) => {
      signal?.throwIfAborted();
      const fact: RecordFact = {
        source: source.name,
        origin: source.origin,
        status: "pending",
      };
      facts.push(fact);
      const index = String(facts.length).padStart(8, "0");
      const directory = join(output, index);
      try {
        if (
          source.size !== null &&
          (source.size > input.options.max_file_bytes ||
            source.size > input.options.max_total_bytes - total)
        ) {
          fact.status = "limited";
          fact.reason =
            "Declared size exceeds caller-selected file or total input budget";
          return;
        }
        await mkdir(directory);
        const extension = extname(source.name)
          .toLowerCase()
          .replace(/[^.a-z0-9]/gu, "");
        const artifact = join(directory, `source${extension || ".bytes"}`);
        const handle = await open(artifact, "wx", 0o600);
        const hash = createHash("sha256");
        const head: Buffer[] = [];
        let headerBytes = 0;
        let bytes = 0;
        const stream = await source.stream().catch(async (cause: unknown) => {
          await handle.close();
          throw cause;
        });
        try {
          for await (const chunk of stream) {
            signal?.throwIfAborted();
            const buffer = Buffer.from(chunk);
            if (
              buffer.length > input.options.max_file_bytes - bytes ||
              buffer.length > input.options.max_total_bytes - total
            )
              throw new Error(
                "Stream exceeds caller-selected resource budget; partial artifact retained",
              );
            hash.update(buffer);
            if (headerBytes < 65536) {
              const part = buffer.subarray(0, 65536 - headerBytes);
              head.push(part);
              headerBytes += part.length;
            }
            let offset = 0;
            while (offset < buffer.length) {
              const written = await handle.write(
                buffer,
                offset,
                buffer.length - offset,
              );
              if (written.bytesWritten === 0)
                throw new Error("Resource write made no progress");
              offset += written.bytesWritten;
            }
            bytes += buffer.length;
            total += buffer.length;
          }
          await handle.sync();
        } finally {
          if ("destroy" in stream && typeof stream.destroy === "function")
            stream.destroy();
          await handle.close();
        }
        Object.assign(fact, {
          artifact,
          bytes,
          sha256: hash.digest("hex"),
          status: "completed",
          conversions: [],
        });
        const conversions = fact.conversions!;
        const header = Buffer.concat(head);
        if (
          input.options.convert_configs &&
          [".bin", ".bytes", ".json", ".cfg"].includes(extension)
        ) {
          const parsed =
            bytes > 16 * 1024 * 1024
              ? {
                  ok: false as const,
                  error: "Configuration exceeds the 16 MiB decoder budget",
                }
              : decodeGameConfig(await readFile(artifact));
          if (parsed.ok) {
            const path = join(directory, "config.json");
            await writeFile(
              path,
              JSON.stringify(
                {
                  interpretations: parsed.value,
                  selection:
                    parsed.value.length === 1
                      ? "single-complete-candidate"
                      : "ambiguous",
                },
                null,
                2,
              ),
              { flag: "wx" },
            );
            conversions.push({
              kind: "configuration",
              status: "completed",
              path,
              protocols: parsed.value.map((value) => value.protocol),
            });
          } else
            conversions.push({
              kind: "configuration",
              status: "unsupported",
              reason: parsed.error,
            });
        }
        const unityOffset = header.indexOf(Buffer.from("UnityFS\0"));
        const unityCandidate =
          unityOffset >= 0 ||
          [".bundle", ".ab", ".unity3d", ".assets"].includes(extension);
        if (unityCandidate) {
          if (input.options.unity_python === undefined)
            conversions.push({
              kind: "unity",
              status: "not-configured",
              reason: "Select a Python interpreter with UnityPy installed",
            });
          else {
            const destination = join(directory, "unity");
            const snapshot = await this.command(
              input.options.unity_python,
              [
                fileURLToPath(
                  new URL(
                    "../../internal/providers/unity_resources.py",
                    import.meta.url,
                  ),
                ),
                artifact,
                destination,
                String(input.options.max_total_bytes),
              ],
              signal,
            );
            await writeFile(
              join(directory, "unity-command.json"),
              JSON.stringify(
                {
                  command: input.options.unity_python,
                  exit_code: snapshot.exitCode,
                  stdout: snapshot.stdout.text,
                  stderr: snapshot.stderr.text,
                },
                null,
                2,
              ),
            );
            if (snapshot.exitCode !== 0)
              conversions.push({
                kind: "unity",
                status: "failed",
                reason: snapshot.stderr.text,
              });
            else {
              const observed = unityResult.parse(
                JSON.parse(snapshot.stdout.text),
              );
              conversions.push({
                kind: "unity",
                ...observed,
                path: destination,
              });
              for (const name of (await readdir(destination)).sort()) {
                if (!/\.(?:dll|pyc|bytes)$/u.test(name)) continue;
                const path = join(destination, name);
                const state = await lstat(path);
                if (state.isFile())
                  await processSource({
                    name,
                    origin: artifact,
                    size: state.size,
                    stream: async () => createReadStream(path, { signal }),
                  });
              }
            }
          }
        }
        const pyc = header.length >= 4 && header[2] === 13 && header[3] === 10;
        const pe = header.subarray(0, 2).equals(Buffer.from("MZ"));
        const engine = pyc
          ? input.options.pycdc
          : pe
            ? input.options.ilspy
            : undefined;
        if (pyc || pe) {
          const kind = pyc ? "python-source" : "managed-source";
          if (engine === undefined)
            conversions.push({
              kind,
              status: "not-configured",
              reason: `Select ${pyc ? "pycdc" : "ilspy"}; an MZ header alone does not prove managed code`,
            });
          else {
            const destination = join(directory, "decompiled");
            await mkdir(destination);
            const snapshot = await this.command(
              engine.command,
              [
                ...engine.args,
                artifact,
                ...(pyc ? [] : ["-p", "-o", destination]),
              ],
              signal,
            );
            await writeFile(
              join(directory, "decompiler-command.json"),
              JSON.stringify(
                {
                  command: engine.command,
                  args: engine.args,
                  exit_code: snapshot.exitCode,
                  stdout: snapshot.stdout.text,
                  stderr: snapshot.stderr.text,
                },
                null,
                2,
              ),
            );
            if (pyc)
              await writeFile(
                join(destination, "source.py"),
                snapshot.stdout.text,
                { flag: "wx" },
              );
            const files = await readdir(destination);
            conversions.push({
              kind,
              status:
                snapshot.exitCode === 0 &&
                files.length > 0 &&
                (!pyc || snapshot.stdout.text.trim().length > 0)
                  ? "completed"
                  : "failed",
              path: destination,
              verification:
                "tool exit and nonempty output; semantic equivalence unverified",
            });
          }
        }
        if (conversions.some((conversion) => conversion.status !== "completed"))
          fact.status = "partial";
      } catch (cause) {
        fact.status = "failed";
        fact.reason = cause instanceof Error ? cause.message : String(cause);
        if (signal?.aborted) throw cause;
      } finally {
        await writeFile(
          join(output, `${index}.record.json`),
          JSON.stringify(fact, null, 2),
          { flag: "wx" },
        );
      }
    };
    try {
      if (input.apk !== undefined) {
        const reader = new ZipArtifactReader(resolve(input.apk), "apk");
        try {
          for await (const entry of reader.entries(signal)) {
            if (entry.kind !== "file") continue;
            const selected =
              input.options.extract_apk ||
              /\.(?:bin|bytes|json|cfg|bundle|ab|unity3d|assets|dll|pyc|lua|luac|jsc)$/iu.test(
                entry.path,
              );
            if (selected)
              await processSource({
                name: entry.path,
                origin: resolve(input.apk),
                size: entry.declaredSize,
                stream: () => reader.open(entry, signal),
              });
          }
        } finally {
          await reader.close();
        }
      }
      const walk = async (path: string, root: string): Promise<void> => {
        signal?.throwIfAborted();
        const stat = await lstat(path);
        if (stat.isSymbolicLink()) {
          facts.push({
            source: path,
            origin: root,
            status: "not-read",
            reason: "Symbolic link is not followed",
          });
          return;
        }
        if (stat.isDirectory()) {
          for (const name of (await readdir(path)).sort())
            await walk(join(path, name), root);
        } else if (stat.isFile())
          await processSource({
            name: relative(root, path) || basename(path),
            origin: path,
            size: stat.size,
            stream: async () => createReadStream(path, { signal }),
          });
      };
      for (const root of input.options.roots)
        await walk(resolve(root), resolve(root));
      await persist();
    } catch (cause) {
      await persist();
      throw cause;
    }
    return {
      output_directory: output,
      manifest: join(output, "manifest.json"),
      examined: facts.length,
      completed: facts.filter((fact) => fact.status === "completed").length,
      failed: facts.filter(
        (fact) => fact.status === "failed" || fact.status === "partial",
      ).length,
      limited: facts.filter((fact) => fact.status === "limited").length,
    };
  }
}
