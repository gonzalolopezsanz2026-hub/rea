import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { JvmRequest } from "../../domain/jvm/jvmAnalysis.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Result } from "../../domain/result.js";

/** Static JVM decompilation with caller-selected inputs and output ownership. */
export interface JvmAnalysisPort {
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  execute(
    request: JvmRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
  close(): Promise<void>;
}
