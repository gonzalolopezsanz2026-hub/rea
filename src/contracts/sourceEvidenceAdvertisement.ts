import { z } from "zod";

import { retainedEvidenceReferenceSchema } from "../domain/evidenceReference.js";

// Hosts forward the advertised input schema to the model on every turn. The
// canonical contract accepts either an inline Evidence record or its exact
// retained reference, but repeating a complete producer record costs its full
// bytes in every following request while showing no argument choice the
// reference does not: the advertisement shows the reference (the same form
// advertisedInputExamples already substitutes for embedded records), and each
// adapter resolves it against its session ledger before authentication.

const referenceAdvertisement = {
  ...z.toJSONSchema(retainedEvidenceReferenceSchema, { io: "input" }),
} as Record<string, unknown>;
delete referenceAdvertisement.$schema;

const referenceProperties =
  typeof referenceAdvertisement.properties === "object" &&
  referenceAdvertisement.properties !== null &&
  !Array.isArray(referenceAdvertisement.properties)
    ? (referenceAdvertisement.properties as Record<string, unknown>)
    : {};

const advertisedSourceEvidenceReference: Record<string, unknown> = {
  ...referenceAdvertisement,
  description:
    "Exact retained reference of the linked Evidence record; the server resolves it from the session Evidence ledger.",
  properties: {
    ...referenceProperties,
    evidence_id: {
      ...(referenceProperties.evidence_id as Record<string, unknown>),
      description: "Evidence identifier of the retained record.",
    },
  },
};

/**
 * Replace an advertised `source_evidence` property with its retained
 * reference. Canonical validation is unchanged: the registered parser still
 * accepts the complete inline record for portable and CLI callers.
 */
export const advertiseSourceEvidenceReference = (
  projected: Record<string, unknown>,
): Record<string, unknown> => {
  const properties = projected.properties;
  if (
    typeof properties !== "object" ||
    properties === null ||
    Array.isArray(properties)
  )
    return projected;
  const fields = properties as Record<string, unknown>;
  if (!Object.hasOwn(fields, "source_evidence")) return projected;
  return {
    ...projected,
    properties: {
      ...fields,
      source_evidence: advertisedSourceEvidenceReference,
    },
  };
};
