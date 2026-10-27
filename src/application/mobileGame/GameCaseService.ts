import { readRegularFileText } from "../RegularFileRead.js";
import { createHash } from "node:crypto";
import { lstat, readdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const STAGES = [
  "01_baseline",
  "02_extract",
  "03_il2cpp",
  "04_resources",
  "05_traffic",
  "06_frida",
  "07_repack",
] as const;
const stagePath = (stage: string): string =>
  ({
    "02_extract": "02_components.evidence.json",
    "03_il2cpp": "03_il2cpp.json",
    "04_resources": "04_resources.json",
    "05_traffic": "05_traffic.json",
  })[stage] ?? stage;
/** Re-observe saved evidence, not directory existence as a success signal. */
export const inspectGameCase = async (
  directory: string,
  signal?: AbortSignal,
) => {
  directory = resolve(directory);
  const scope = JSON.parse(
    await readRegularFileText(join(directory, "scope.json"), {
      symlinks: "reject",
      signal,
      admit: (state) => {
        if (state.size > 1024 * 1024)
          throw new Error("Case scope exceeds 1 MiB metadata budget");
      },
    }),
  ) as unknown;
  const { z } = await import("zod");
  const admitted = z
    .object({
      game: z.string(),
      apk: z.object({
        path: z.string(),
        sha256: z.string().regex(/^[a-f0-9]{64}$/u),
      }),
    })
    .parse(scope);
  const files: { path: string; bytes: number; sha256: string }[] = [];
  const walk = async (path: string, prefix: string): Promise<void> => {
    signal?.throwIfAborted();
    const stat = await lstat(path);
    if (stat.isSymbolicLink())
      throw new Error(`Case evidence contains a symbolic link: ${prefix}`);
    if (stat.isDirectory()) {
      for (const name of (await readdir(path)).sort())
        await walk(join(path, name), prefix ? `${prefix}/${name}` : name);
    } else if (stat.isFile()) {
      const { createReadStream } = await import("node:fs");
      const hash = createHash("sha256");
      let bytes = 0;
      for await (const chunk of createReadStream(path, { signal })) {
        hash.update(chunk);
        bytes += chunk.length;
      }
      files.push({ path: prefix, bytes, sha256: hash.digest("hex") });
    }
  };
  await walk(directory, "");
  const recorded = JSON.parse(
    await readRegularFileText(join(directory, "check.json"), {
      symlinks: "reject",
      signal,
      admit: (state) => {
        if (state.size > 1024 * 1024)
          throw new Error("Case checks exceed 1 MiB metadata budget");
      },
    }),
  ) as unknown;
  const stageChecks = z
    .object({
      checks: z.array(z.object({ stage: z.string(), status: z.string() })),
    })
    .parse(recorded).checks;
  const checks = STAGES.map((stage) => {
    const path = stagePath(stage);
    const artifacts = files.filter(
      (file) => file.path === path || file.path.startsWith(`${stage}/`),
    );
    return {
      stage,
      status:
        stage === "06_frida" || stage === "07_repack"
          ? "not-tested"
          : artifacts.length === 0
            ? "not-tested"
            : "evidence-present",
      recorded_statuses: stageChecks.filter((check) =>
        check.stage.startsWith(
          {
            "01_baseline": "baseline",
            "02_extract": "components",
            "03_il2cpp": "il2cpp",
            "04_resources": "resources",
            "05_traffic": "traffic",
            "06_frida": "dynamic",
            "07_repack": "repack",
          }[stage] ?? stage,
        ),
      ),
      artifacts: artifacts.map((file) => file.path),
      limitation:
        "Presence and hashes do not establish stage correctness or a vulnerability",
    };
  });
  return {
    case_directory: directory,
    scope: admitted,
    checks,
    files,
    status: "partial" as const,
    limitations: [
      "This checks saved evidence identity and coverage, not runtime behavior or authorization.",
      "Source trees may change during inspection; no atomic case snapshot is claimed.",
    ],
  };
};

export const renderGameCaseReport = (
  game: string,
  apk: { path: string; sha256: string },
  facts: {
    stage: string;
    status: string;
    artifacts?: string[];
    recorded_statuses?: { stage: string; status: string }[];
  }[],
): string =>
  [
    `# ${game} 游戏安全评估报告`,
    "",
    "## 风险概览",
    "",
    "本报告记录实际覆盖和证据。自动候选尚未确认为漏洞；风险数量未知，不按零风险报告。",
    "",
    `- APK：\`${apk.path}\``,
    `- SHA-256：\`${apk.sha256}\``,
    "",
    "## 客户端安全",
    "",
    ...facts
      .filter((fact) => !fact.stage.includes("traffic"))
      .flatMap((fact) => [
        `### ${fact.stage}`,
        "",
        `状态：${fact.status}`,
        ...(fact.recorded_statuses ?? []).map(
          (record) => `- 原阶段记录：${record.stage} = ${record.status}`,
        ),
        ...(fact.artifacts ?? []).map((path) => `- 证据：\`${path}\``),
        "",
      ]),
    "## 应用层安全",
    "",
    "### 协议与流量",
    "",
    ...facts
      .filter((fact) => fact.stage.includes("traffic"))
      .map(
        (fact) =>
          `状态：${fact.status}；证据：${(fact.artifacts ?? []).join(", ") || "见阶段记录"}`,
      ),
    "",
    "### 后端强校验",
    "",
    "未测：自动静态流程没有测试账号、业务操作或服务端证据，不能确定战斗、抽卡、充值及数值同步是否由服务端权威控制。",
    "",
    "## 总结与建议",
    "",
    "先验证候选的实际影响，再评定风险。设备、协议、动态调试、重打包及保护恢复仅能按独立授权范围与工具契约执行。",
    "",
  ].join("\n");

export const writeGameCaseReport = async (
  directory: string,
  signal?: AbortSignal,
) => {
  const inspected = await inspectGameCase(directory, signal);
  signal?.throwIfAborted();
  const path = join(inspected.case_directory, "report.generated.md");
  // A regeneration never overwrites the analyst's edited report.
  await writeFile(
    path,
    renderGameCaseReport(
      inspected.scope.game,
      inspected.scope.apk,
      inspected.checks,
    ),
    { flag: "wx" },
  );
  return { report: path, coverage: inspected.status, checks: inspected.checks };
};
