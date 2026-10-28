/** Expected RPC intake failure (transport, account shape, or layout). */
export class SolanaRpcFailure extends Error {}

export const BPF_LOADER_UPGRADEABLE =
  "BPFLoaderUpgradeab1e11111111111111111111111";
export const DEFAULT_SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com";

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Decode a base58 string with Node stdlib only; undefined when malformed. */
export const decodeBase58 = (value: string): Uint8Array | undefined => {
  if (value.length === 0) return undefined;
  let leadingZeros = 0;
  while (leadingZeros < value.length && value[leadingZeros] === "1")
    leadingZeros += 1;
  const size =
    Math.floor(((value.length - leadingZeros) * Math.log(58)) / Math.log(256)) +
    1;
  const bytes = new Uint8Array(size);
  let length = 0;
  for (let index = leadingZeros; index < value.length; index += 1) {
    const digit = BASE58_ALPHABET.indexOf(value[index] ?? "");
    if (digit < 0) return undefined;
    let carry = digit;
    let consumed = 0;
    for (
      let position = size - 1;
      position >= 0 && (carry !== 0 || consumed < length);
      position -= 1
    ) {
      carry += 58 * (bytes[position] ?? 0);
      bytes[position] = carry % 256;
      carry = Math.floor(carry / 256);
      consumed += 1;
    }
    if (carry !== 0) return undefined;
    length = consumed;
  }
  let start = size - length;
  while (start < size && bytes[start] === 0) start += 1;
  const result = new Uint8Array(leadingZeros + (size - start));
  result.set(bytes.subarray(start), leadingZeros);
  return result;
};

/** Encode bytes as base58 (used for the ProgramData account address). */
export const encodeBase58 = (bytes: Uint8Array): string => {
  if (bytes.length === 0) return "";
  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0)
    leadingZeros += 1;
  const size =
    Math.floor(((bytes.length - leadingZeros) * Math.log(256)) / Math.log(58)) +
    1;
  const digits = new Uint8Array(size);
  let length = 0;
  for (let index = leadingZeros; index < bytes.length; index += 1) {
    let carry = bytes[index] ?? 0;
    let consumed = 0;
    for (
      let position = size - 1;
      position >= 0 && (carry !== 0 || consumed < length);
      position -= 1
    ) {
      carry += 256 * (digits[position] ?? 0);
      digits[position] = carry % 58;
      carry = Math.floor(carry / 58);
      consumed += 1;
    }
    length = consumed;
  }
  let start = size - length;
  while (start < size && digits[start] === 0) start += 1;
  let result = "1".repeat(leadingZeros);
  for (let index = start; index < size; index += 1)
    result += BASE58_ALPHABET[digits[index] ?? 0] ?? "1";
  return result;
};

export interface SolanaProgramFetch {
  readonly elfBytes: Uint8Array;
  readonly programDataAccount: string | null;
  readonly slot: number | null;
}

interface AccountInfo {
  readonly data: Uint8Array;
  readonly owner: string;
  readonly executable: boolean;
}

type FetchLike = typeof fetch;

/** One JSON-RPC getAccountInfo call with base64 encoding; null when absent. */
const getAccountInfo = async (
  fetchImpl: FetchLike,
  rpcUrl: string,
  address: string,
  signal: AbortSignal | undefined,
): Promise<AccountInfo | null> => {
  let response: Response;
  try {
    response = await fetchImpl(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "getAccountInfo",
        params: [address, { encoding: "base64", commitment: "finalized" }],
      }),
      ...(signal === undefined ? {} : { signal }),
    });
  } catch (cause) {
    throw new SolanaRpcFailure(
      `Solana RPC request to ${rpcUrl} failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
  if (!response.ok)
    throw new SolanaRpcFailure(
      `Solana RPC ${rpcUrl} answered HTTP ${String(response.status)}.`,
    );
  const payload: unknown = await response.json().catch((cause: unknown) => {
    throw new SolanaRpcFailure("Solana RPC answered non-JSON content.", {
      cause,
    });
  });
  if (typeof payload !== "object" || payload === null)
    throw new SolanaRpcFailure("Solana RPC answered a malformed envelope.");
  const envelope = payload as {
    readonly result?: { readonly value?: unknown } | null;
    readonly error?: { readonly message?: string } | null;
  };
  if (envelope.error !== null && envelope.error !== undefined)
    throw new SolanaRpcFailure(
      `Solana RPC error: ${envelope.error.message ?? "unknown"}.`,
    );
  const value = envelope.result?.value;
  if (value === null || value === undefined) return null;
  if (typeof value !== "object")
    throw new SolanaRpcFailure("Solana RPC account value is malformed.");
  const account = value as {
    readonly data?: unknown;
    readonly owner?: unknown;
    readonly executable?: unknown;
  };
  const dataField = account.data;
  if (
    !Array.isArray(dataField) ||
    typeof dataField[0] !== "string" ||
    dataField[1] !== "base64"
  )
    throw new SolanaRpcFailure(
      "Solana RPC account data did not arrive as base64.",
    );
  return {
    data: Uint8Array.from(Buffer.from(dataField[0], "base64")),
    owner: typeof account.owner === "string" ? account.owner : "",
    executable: account.executable === true,
  };
};

/**
 * Fetch a program's executable bytes read-only. Upgradeable-loader programs
 * resolve through their ProgramData account (4-byte tag 3, u64 slot,
 * optional authority); legacy-loader accounts hold the ELF directly.
 */
export const fetchSolanaProgramElf = async (
  programId: string,
  rpcUrl: string,
  options: {
    readonly signal?: AbortSignal;
    readonly fetchImpl?: FetchLike;
  } = {},
): Promise<SolanaProgramFetch> => {
  const decoded = decodeBase58(programId);
  if (decoded === undefined || decoded.length !== 32)
    throw new SolanaRpcFailure(
      `Program id ${programId} is not a base58-encoded 32-byte public key.`,
    );
  const fetchImpl = options.fetchImpl ?? fetch;
  const account = await getAccountInfo(
    fetchImpl,
    rpcUrl,
    programId,
    options.signal,
  );
  if (account === null)
    throw new SolanaRpcFailure(
      `No account exists at ${programId} on the selected endpoint.`,
    );
  if (account.owner !== BPF_LOADER_UPGRADEABLE) {
    if (
      account.data[0] === 0x7f &&
      account.data[1] === 0x45 &&
      account.data[2] === 0x4c &&
      account.data[3] === 0x46
    )
      return {
        elfBytes: account.data,
        programDataAccount: null,
        slot: null,
      };
    throw new SolanaRpcFailure(
      `Account ${programId} is owned by ${account.owner || "an unknown program"} and does not hold an ELF directly; only BPF Loader Upgradeable programs resolve through ProgramData.`,
    );
  }
  const view = new DataView(
    account.data.buffer,
    account.data.byteOffset,
    account.data.byteLength,
  );
  if (account.data.length < 36 || view.getUint32(0, true) !== 2)
    throw new SolanaRpcFailure(
      `Account ${programId} is not an upgradeable Program account.`,
    );
  const programDataAccount = encodeBase58(account.data.subarray(4, 36));
  const programData = await getAccountInfo(
    fetchImpl,
    rpcUrl,
    programDataAccount,
    options.signal,
  );
  if (programData === null)
    throw new SolanaRpcFailure(
      `ProgramData account ${programDataAccount} for ${programId} was not found.`,
    );
  const data = programData.data;
  const dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (data.length < 13 || dataView.getUint32(0, true) !== 3)
    throw new SolanaRpcFailure(
      `ProgramData account ${programDataAccount} has an unexpected layout.`,
    );
  const slot = Number(dataView.getBigUint64(4, true));
  const authorityPresent = data[12] === 1;
  const elfStart = authorityPresent ? 45 : 13;
  if (data.length <= elfStart)
    throw new SolanaRpcFailure(
      `ProgramData account ${programDataAccount} carries no ELF bytes.`,
    );
  return {
    elfBytes: data.subarray(elfStart),
    programDataAccount,
    slot,
  };
};
