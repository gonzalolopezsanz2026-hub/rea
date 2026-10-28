import type { EvidenceMcpServer } from "../EvidenceMcpServer.js";
import type { ServerContext } from "@modelcontextprotocol/server";
import { runAdmittedToolOperation } from "../admittedToolOperation.js";

import { projectAndroidJniNamesEvidence } from "../../application/android/AndroidJniNamesService.js";
import { toolContract } from "../../contracts/toolContracts.js";
import { logToolExecution } from "../toolLogging.js";
import { toolRegistrationOptions } from "../toolRegistrationOptions.js";
import { recordResult } from "./helpers.js";
import type { ApplicationToolRegistration } from "./types.js";

/** Register the execution-free Android JNI/JNA name projection tool. */
export const registerProjectAndroidJniNamesTool = (
  server: EvidenceMcpServer,
  options: ApplicationToolRegistration,
): void => {
  const contract = toolContract("project_android_jni_names");
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input: unknown, request: ServerContext) =>
      runAdmittedToolOperation(
        server,
        options.withAdmittedAnalysis,
        contract.name,
        request.mcpReq.signal,
        async () => {
          const result = await logToolExecution(
            options.logger,
            contract.name,
            () =>
              Promise.resolve(
                projectAndroidJniNamesEvidence(input, options.evidenceById),
              ),
          );
          if (!result.ok)
            return server.delivery.toCallToolResult(result, contract);
          return recordResult(
            { ...options, delivery: server.delivery },
            contract,
            result.value,
          );
        },
      ),
  );
};
