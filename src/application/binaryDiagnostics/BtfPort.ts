import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectBtfInput, Btf } from "../../domain/native/btf.js";
import type { Result } from "../../domain/result.js";

/** Stable read and BTF decoding, independent of a disassembler session. */
export interface BtfPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectBtfInput,
    options?: ExecutionOptions,
  ): Promise<Result<Btf, AnalysisError>>;
}
