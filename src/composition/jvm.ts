import type { JvmAnalysisPort } from "../application/jvm/JvmAnalysisPort.js";
import { VineflowerProvider } from "../jvm/VineflowerProvider.js";

/** Compose a fresh bring-your-own Vineflower provider without starting it. */
export const createJvmAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): JvmAnalysisPort => new VineflowerProvider({ environment });
