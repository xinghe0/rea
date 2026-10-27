import type { Result } from "../domain/result.js";
import {
  parseScrcpyConfiguration,
  type ScrcpyConfiguration,
} from "../scrcpy/ScrcpyConfiguration.js";
import {
  createScrcpyMcpConnection,
  type ScrcpyMcpConnection,
} from "../scrcpy/ScrcpyMcpConnection.js";
import type { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { ScrcpyProvider } from "../scrcpy/ScrcpyProvider.js";

/** Optional external provider composition. It never starts scrcpy by itself. */
export const createScrcpyMcpProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): Result<
  {
    readonly configuration: ScrcpyConfiguration;
    readonly connection: ScrcpyMcpConnection;
    readonly provider: ScrcpyProvider;
  },
  AnalysisInputError
> => {
  const configuration = parseScrcpyConfiguration(environment);
  return configuration.ok
    ? (() => {
        const connection = createScrcpyMcpConnection(configuration.value);
        return {
          ok: true,
          value: {
            configuration: configuration.value,
            connection,
            provider: new ScrcpyProvider(connection),
          },
        };
      })()
    : configuration;
};
