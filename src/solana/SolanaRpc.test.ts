import { expect, it } from "vitest";
import {
  BPF_LOADER_UPGRADEABLE,
  decodeBase58,
  encodeBase58,
  fetchSolanaProgramElf,
  SolanaRpcFailure,
} from "./SolanaRpc.js";

const PUMP_AMM = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA";

it("round-trips base58 public keys exactly", () => {
  for (const value of [
    PUMP_AMM,
    BPF_LOADER_UPGRADEABLE,
    "11111111111111111111111111111111",
  ]) {
    const decoded = decodeBase58(value);
    expect(decoded).toHaveLength(32);
    expect(encodeBase58(decoded as Uint8Array)).toBe(value);
  }
  expect(decodeBase58("0OIl")).toBeUndefined();
  expect(decodeBase58("")).toBeUndefined();
});

const jsonResponse = (value: unknown): Response =>
  new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { value } }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

const accountValue = (
  data: Uint8Array,
  owner: string,
  executable = true,
): unknown => ({
  data: [Buffer.from(data).toString("base64"), "base64"],
  owner,
  executable,
  lamports: 1,
  rentEpoch: 0,
});

it("resolves an upgradeable program through its ProgramData account", async () => {
  const elf = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
  const programDataAddress = decodeBase58(BPF_LOADER_UPGRADEABLE) as Uint8Array;
  const programAccount = new Uint8Array(36);
  new DataView(programAccount.buffer).setUint32(0, 2, true);
  programAccount.set(programDataAddress, 4);
  const programData = new Uint8Array(45 + elf.length);
  const dataView = new DataView(programData.buffer);
  dataView.setUint32(0, 3, true);
  dataView.setBigUint64(4, 4242n, true);
  programData[12] = 1;
  programData.set(elf, 45);
  const calls: string[] = [];
  const fetchImpl = (async (_url: unknown, init?: { body?: unknown }) => {
    const body = JSON.parse(String(init?.body)) as {
      params: readonly string[];
    };
    const address = body.params[0] as string;
    calls.push(address);
    return jsonResponse(
      address === PUMP_AMM
        ? accountValue(programAccount, BPF_LOADER_UPGRADEABLE)
        : accountValue(programData, BPF_LOADER_UPGRADEABLE, false),
    );
  }) as typeof fetch;
  const fetched = await fetchSolanaProgramElf(PUMP_AMM, "https://rpc.invalid", {
    fetchImpl,
  });
  expect(calls).toEqual([PUMP_AMM, BPF_LOADER_UPGRADEABLE]);
  expect(fetched.programDataAccount).toBe(BPF_LOADER_UPGRADEABLE);
  expect(fetched.slot).toBe(4242);
  expect(Array.from(fetched.elfBytes)).toEqual(Array.from(elf));
});

it("accepts a legacy-loader account holding the ELF directly", async () => {
  const elf = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
  const fetchImpl = (async () =>
    jsonResponse(
      accountValue(elf, "BPFLoader2111111111111111111111111111111111"),
    )) as typeof fetch;
  const fetched = await fetchSolanaProgramElf(PUMP_AMM, "https://rpc.invalid", {
    fetchImpl,
  });
  expect(fetched.programDataAccount).toBeNull();
  expect(Array.from(fetched.elfBytes)).toEqual(Array.from(elf));
});

it("fails closed for missing accounts and malformed program ids", async () => {
  const fetchImpl = (async () => jsonResponse(null)) as unknown as typeof fetch;
  await expect(
    fetchSolanaProgramElf(PUMP_AMM, "https://rpc.invalid", { fetchImpl }),
  ).rejects.toThrow(SolanaRpcFailure);
  await expect(
    fetchSolanaProgramElf("not-a-key", "https://rpc.invalid", { fetchImpl }),
  ).rejects.toThrow(SolanaRpcFailure);
});
