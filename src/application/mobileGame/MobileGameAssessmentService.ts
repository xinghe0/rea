import type { GameResourceProvider } from "../../mobileGame/GameResourceProvider.js";
import type { AdbDeviceAnalysisService } from "../adb/AdbDeviceAnalysisService.js";
import { renderGameCaseReport } from "./GameCaseService.js";
import { extractGameMetadata } from "./MobileGameMetadataExtraction.js";
import { createHash } from "node:crypto";
import { access, mkdir, writeFile } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { join, resolve } from "node:path";
import {
  mobileGameAssessmentInputSchema,
  type MobileGameAssessmentResult,
} from "../../domain/mobileGame/mobileGameAssessment.js";
import {
  collectDeviceBaseline,
  inspectApkManifest,
  listApkEntries,
  scanApkResources,
  scanApkSensitiveStrings,
} from "./MobileGameStaticAnalysis.js";

const sha256File = async (
  path: string,
  signal?: AbortSignal,
): Promise<string> =>
  new Promise((done, fail) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path, { signal });
    stream.on("data", (chunk: Buffer) => hash.update(chunk));
    stream.once("error", fail);
    stream.once("end", () => done(hash.digest("hex")));
  });

const markdown = (report: Record<string, unknown>): string => {
  const manifest = report.manifest as Record<string, unknown>;
  const device = report.device as Record<string, unknown>;
  const resource = report.resource_summary as Record<string, unknown>;
  const sensitive = report.sensitive_summary as Record<string, unknown>;
  return [
    "# Mobile game assessment",
    "",
    `- APK: \`${String(report.apk)}\``,
    `- SHA-256: \`${String(report.sha256)}\``,
    `- Package: \`${String(manifest.package_name ?? "unknown")}\``,
    `- Target SDK: \`${String(manifest.target_sdk ?? "unknown")}\``,
    `- Device: \`${String(device.serial ?? "not connected")}\``,
    `- Engines: ${String((report.engines as string[]).join(", ") || "unknown")}`,
    `- Packer candidates: ${String((report.packer_indicators as string[]).join(", ") || "none")}`,
    `- Resources recognized/candidates: ${String(resource.recognized)}/${String(resource.candidates)}`,
    `- Sensitive candidates: ${String(sensitive.hit_count)}`,
    "",
    "## Not tested",
    "",
    "- Dynamic injection or Frida probes",
    "- Traffic mutation or replay",
    "- Repackaging or installation",
    "- Protection bypass or key recovery",
    "",
    "## Limitations",
    "",
    "- Static and passive observations only.",
    "- Component authorization and runtime behavior require separate evidence.",
    "",
  ].join("\n");
};

import type { PcapAnalysisService } from "../pcap/PcapAnalysisService.js";
import type { AndroidAnalysisService } from "../android/AndroidAnalysisService.js";
import type { Il2cppMetadataService } from "../il2cpp/Il2cppMetadataService.js";
import type { ApkSignatureService } from "../apkSignature/ApkSignatureService.js";

export class MobileGameAssessmentService {
  constructor(
    private readonly signatures?: Pick<
      ApkSignatureService,
      "inspect" | "close"
    >,
    private readonly il2cpp?: Pick<Il2cppMetadataService, "inspect">,
    private readonly android?: Pick<AndroidAnalysisService, "execute">,
    private readonly pcap?: Pick<PcapAnalysisService, "execute">,
    private readonly resources?: GameResourceProvider,
    private readonly adb?: AdbDeviceAnalysisService,
  ) {}
  async assess(
    input: unknown,
    signal?: AbortSignal,
  ): Promise<MobileGameAssessmentResult> {
    const parsed = mobileGameAssessmentInputSchema.parse(input);
    signal = AbortSignal.any([
      ...(signal === undefined ? [] : [signal]),
      AbortSignal.timeout(parsed.timeout_ms ?? 180_000),
    ]);
    signal.throwIfAborted();
    const apk = resolve(parsed.apk);
    await access(apk);
    if (parsed.device_package !== undefined && parsed.serial === undefined)
      throw new Error(
        "Device resource acquisition requires an explicit serial",
      );
    const digest = await sha256File(apk, signal);
    const caseDirectory = resolve(parsed.case_root, parsed.game, "analysis");
    const baseline = join(caseDirectory, "01_baseline");
    const outDir = join(baseline, "triage");
    await mkdir(resolve(parsed.case_root, parsed.game), { recursive: true });
    await mkdir(caseDirectory);
    for (const stage of [
      "01_baseline",
      "02_extract",
      "03_il2cpp",
      "04_resources",
      "05_traffic",
      "06_frida",
      "07_repack",
      "repro",
    ])
      await mkdir(join(caseDirectory, stage));
    await mkdir(outDir);
    await writeFile(
      join(caseDirectory, "scope.json"),
      `${JSON.stringify({ schema_version: 1, game: parsed.game, apk: { path: apk, sha256: digest }, authorization: "static-and-passive-default", generated_at: new Date().toISOString() }, null, 2)}\n`,
      "utf8",
    );
    const entries = await listApkEntries(apk, signal);
    const manifest = await inspectApkManifest(apk, signal);
    const components =
      this.android === undefined
        ? null
        : await this.android.execute(
            "inspect_android_package",
            { path: apk },
            signal === undefined ? {} : { signal },
          );
    const componentEvidence =
      components === null
        ? { status: "not-configured" }
        : components.ok
          ? components.value
          : { status: "failed", reason: components.error.message };
    await writeFile(
      join(caseDirectory, "02_components.evidence.json"),
      JSON.stringify(componentEvidence, null, 2),
      { flag: "wx" },
    );
    const signature =
      this.signatures === undefined
        ? null
        : await this.signatures.inspect(
            { path: apk, detail: "complete" },
            signal === undefined ? {} : { signal },
          );
    if (signature !== null)
      await writeFile(
        join(baseline, "signature.json"),
        JSON.stringify(
          signature.ok
            ? signature.value
            : { status: "failed", reason: signature.error.message },
          null,
          2,
        ),
        { flag: "wx" },
      );
    const device = await collectDeviceBaseline(signal, parsed.serial);
    const il2cppCandidates = entries.filter(
      (entry) =>
        entry.path === "assets/bin/Data/Managed/Metadata/global-metadata.dat" ||
        entry.path.toLowerCase().endsWith("libil2cpp.so"),
    );
    let metadataEvidence = null;
    let selectedMetadata = parsed.metadata_path;
    let metadataSource = null;
    let selectedBinary = parsed.binary_path;
    if (selectedMetadata === undefined) {
      const candidates = entries.filter((entry) =>
        entry.path.endsWith("/global-metadata.dat"),
      );
      if (candidates.length === 1) {
        const directory = join(caseDirectory, "03_il2cpp");
        metadataSource = await extractGameMetadata(
          apk,
          candidates[0]!.path,
          join(directory, "global-metadata.dat"),
          signal,
        );
        selectedMetadata = metadataSource.path;
      }
    }
    if (selectedBinary === undefined && selectedMetadata !== undefined) {
      const binaries = entries.filter((entry) =>
        /(?:^|\/)libil2cpp\.so$/u.test(entry.path),
      );
      if (binaries.length === 1) {
        const directory = join(caseDirectory, "03_il2cpp");
        await mkdir(directory, { recursive: true });
        const binary = await extractGameMetadata(
          apk,
          binaries[0]!.path,
          join(directory, "libil2cpp.so"),
          signal,
        );
        selectedBinary = binary.path;
        await writeFile(
          join(directory, "binary-source.json"),
          JSON.stringify(binary, null, 2),
          { flag: "wx" },
        );
      }
    }
    if (selectedMetadata !== undefined && this.il2cpp !== undefined) {
      const inspected = await this.il2cpp.inspect(
        {
          path: resolve(selectedMetadata),
          detail: "complete",
          ...(selectedBinary === undefined
            ? {}
            : { binary_path: resolve(selectedBinary) }),
        },
        signal === undefined ? {} : { signal },
      );
      metadataEvidence = inspected.ok
        ? inspected.value
        : { status: "failed", reason: inspected.error.message };
      await writeFile(
        join(caseDirectory, "03_il2cpp.evidence.json"),
        JSON.stringify(metadataEvidence, null, 2),
        { flag: "wx" },
      );
    }
    const traffic =
      parsed.capture_path === undefined || this.pcap === undefined
        ? null
        : await this.pcap.execute(
            "inspect_pcap_capture",
            { path: resolve(parsed.capture_path) },
            { signal },
          );
    if (traffic !== null)
      await writeFile(
        join(caseDirectory, "05_traffic.json"),
        JSON.stringify(
          traffic.ok
            ? traffic.value
            : { status: "failed", reason: traffic.error.message },
          null,
          2,
        ),
        { flag: "wx" },
      );
    let deviceResources = null;
    if (
      parsed.device_package !== undefined &&
      parsed.serial !== undefined &&
      this.resources !== undefined &&
      this.adb !== undefined
    ) {
      deviceResources = await this.resources.acquireDeviceResources(
        this.adb,
        parsed.serial,
        parsed.device_package,
        join(caseDirectory, "04_resources", "device_files"),
        signal,
      );
    }
    const conversion =
      parsed.resources === undefined || this.resources === undefined
        ? null
        : await this.resources.convert(
            {
              apk,
              output_directory: join(
                caseDirectory,
                "04_resources",
                "converted",
              ),
              options: {
                ...parsed.resources,
                roots: [
                  ...parsed.resources.roots,
                  ...(deviceResources?.roots ?? []),
                ],
              },
            },
            signal,
          );
    const resourceFacts = await scanApkResources(apk, entries, signal);
    const sensitiveHits = await scanApkSensitiveStrings(apk, entries, signal);
    const report = {
      schema_version: 1,
      apk: apk.split("/").pop() ?? apk,
      sha256: digest,
      entries: entries.length,
      dex: entries.filter((entry) => entry.path.endsWith(".dex")).length,
      engines: [
        ...new Set(
          entries.flatMap(({ path }) =>
            Object.entries({
              libil2cpp: "Unity IL2CPP",
              libunity: "Unity",
              libmono: "Unity Mono",
              libcocos: "Cocos",
              libue4: "Unreal",
              libue5: "Unreal",
              libunreal: "Unreal",
              libflutter: "Flutter",
            })
              .filter(([marker]) => path.split("/").pop()?.startsWith(marker))
              .map(([, engine]) => engine),
          ),
        ),
      ],
      packer_indicators: entries
        .filter(({ path }) =>
          /lib(?:jiagu|dexhelper|shell|mobisec|nesec)/iu.test(path),
        )
        .map(({ path }) => path),
      manifest,
      signature:
        signature?.ok === true ? signature.value.evidence_id : "unavailable",
      device,
      il2cpp: {
        candidates: il2cppCandidates,
        metadata_evidence: metadataEvidence,
        extracted_source: metadataSource,
        status:
          il2cppCandidates.length === 0 ? "not-observed" : "route-available",
      },
      resource_summary: {
        total: resourceFacts.length,
        recognized: resourceFacts.filter((fact) => fact.type !== "unknown")
          .length,
        candidates: resourceFacts.filter((fact) => fact.encrypted === null)
          .length,
      },
      sensitive_summary: {
        hit_count: sensitiveHits.length,
        types: [...new Set(sensitiveHits.map((hit) => hit.type))],
      },
    };
    if ((await sha256File(apk, signal)) !== digest)
      throw new Error("APK changed during assessment");
    signal?.throwIfAborted();
    const jsonPath = join(outDir, "triage.json");
    const markdownPath = join(outDir, "triage.md");
    await writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    await writeFile(markdownPath, markdown(report), "utf8");
    await writeFile(
      join(caseDirectory, "02_extract.json"),
      `${JSON.stringify({ source: { path: apk, sha256: digest }, manifest, component_evidence: componentEvidence }, null, 2)}\n`,
      "utf8",
    );
    await writeFile(
      join(caseDirectory, "03_il2cpp.json"),
      `${JSON.stringify({ source: { path: apk, sha256: digest }, ...report.il2cpp }, null, 2)}\n`,
      "utf8",
    );
    await writeFile(
      join(caseDirectory, "04_resources.json"),
      `${JSON.stringify({ source: { path: apk, sha256: digest }, facts: resourceFacts, sensitive_hits: sensitiveHits, coverage: "Pattern candidates retain caller-supplied source values; matches do not establish secrecy or a vulnerability." }, null, 2)}\n`,
      "utf8",
    );
    await writeFile(join(caseDirectory, "report.md"), markdown(report), "utf8");
    const checks = [
      {
        stage: "resources.conversion",
        status:
          conversion === null
            ? "not-selected"
            : conversion.failed > 0 || conversion.limited > 0
              ? "partial"
              : "completed",
        artifact: conversion?.manifest ?? null,
      },
      {
        stage: "resources.device",
        status:
          deviceResources === null
            ? "not-selected"
            : deviceResources.failed > 0
              ? "partial"
              : "completed",
      },
      {
        stage: "traffic",
        status:
          parsed.capture_path === undefined
            ? "not-selected"
            : traffic === null
              ? "not-configured"
              : traffic.ok
                ? "completed"
                : "failed",
      },
      {
        stage: "baseline.signature",
        status:
          signature === null
            ? "not-configured"
            : signature.ok
              ? "completed"
              : "failed",
      },
      {
        stage: "components",
        status:
          components === null
            ? "not-configured"
            : components.ok
              ? "completed"
              : "failed",
      },
      {
        stage: "device",
        status: device.state === "device" ? "completed" : device.state,
      },
      {
        stage: "il2cpp",
        status:
          metadataEvidence === null
            ? il2cppCandidates.length === 0
              ? "not-observed"
              : "not-tested"
            : "evidence_id" in metadataEvidence
              ? "completed"
              : "failed",
      },
      {
        stage: "resources.headers",
        status: "completed",
        examined: resourceFacts.length,
        total: entries.length,
      },
      {
        stage: "resources.text",
        status: "partial",
        reason:
          "At most 524288 bytes per text member; pattern candidates are not confirmed vulnerabilities",
      },
    ];
    await writeFile(
      join(baseline, "device.json"),
      JSON.stringify(device, null, 2),
      { flag: "wx" },
    );
    await writeFile(
      join(caseDirectory, "02_extract", "components.json"),
      JSON.stringify(componentEvidence, null, 2),
      { flag: "wx" },
    );
    await writeFile(
      join(caseDirectory, "03_il2cpp", "analysis.json"),
      JSON.stringify(report.il2cpp, null, 2),
      { flag: "wx" },
    );
    await writeFile(
      join(caseDirectory, "04_resources", "scan.json"),
      JSON.stringify(
        {
          source: { path: apk, sha256: digest },
          facts: resourceFacts,
          sensitive_hits: sensitiveHits,
        },
        null,
        2,
      ),
      { flag: "wx" },
    );
    await writeFile(
      join(caseDirectory, "05_traffic", "analysis.json"),
      JSON.stringify(
        traffic === null
          ? {
              status: "not-tested",
              reason: "No capture selected or provider unavailable",
            }
          : traffic.ok
            ? traffic.value
            : { status: "failed", reason: traffic.error.message },
        null,
        2,
      ),
      { flag: "wx" },
    );
    for (const [stage, reason] of [
      ["06_frida", "No dynamic instrumentation requested by static assessment"],
      [
        "07_repack",
        "No repackaging or installation requested by static assessment",
      ],
    ])
      await writeFile(
        join(caseDirectory, stage!, "status.json"),
        JSON.stringify({ status: "not-tested", reason }, null, 2),
        { flag: "wx" },
      );
    await writeFile(
      join(caseDirectory, "check.json"),
      JSON.stringify(
        {
          status: checks.some((check) => check.status === "failed")
            ? "failed"
            : "partial",
          checks,
          not_tested: [
            "dynamic",
            "traffic-mutation-or-replay",
            "repack",
            "protection-recovery",
          ],
        },
        null,
        2,
      ),
      "utf8",
    );
    await writeFile(
      join(caseDirectory, "report.md"),
      renderGameCaseReport(parsed.game, { path: apk, sha256: digest }, checks),
    );
    await writeFile(join(caseDirectory, "README.md"), markdown(report));
    return {
      case_directory: caseDirectory,
      input_sha256: digest,
      triage_json: jsonPath,
      triage_markdown: markdownPath,
      status: checks.some((check) => check.status === "failed")
        ? "failed"
        : "partial",
      check_json: join(caseDirectory, "check.json"),
      report_markdown: join(caseDirectory, "report.md"),
      stages: [
        "01_baseline",
        "02_extract",
        "03_il2cpp",
        "04_resources",
        ...(traffic === null ? [] : ["05_traffic"]),
      ],
      not_tested: [
        "dynamic probes",
        "traffic mutation/replay",
        "repack/install",
        "protection or key recovery",
      ],
    };
  }
}
