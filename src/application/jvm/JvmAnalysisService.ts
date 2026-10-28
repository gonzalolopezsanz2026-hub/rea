import type { JvmAnalysisPort } from "./JvmAnalysisPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  jvmRequestSchema,
  type JvmOperation,
} from "../../domain/jvm/jvmAnalysis.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP admission and provenance for static JVM reconstruction. */
export class JvmAnalysisService {
  constructor(readonly provider: JvmAnalysisPort) {}

  execute(
    operation: JvmOperation,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      jvmRequestSchema,
      this.provider,
      operation === "inspect_jvm_decompiler" ? "observed" : "derived",
    );
  }
}
