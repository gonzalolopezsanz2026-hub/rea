import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it } from "vitest";

import { SolanaProgramProvider } from "./SolanaProgramProvider.js";
import type { SolanaHandoff } from "./SolanaHandoff.js";

/** Encode one sBPF word: opcode, register pair, i16 offset, i32 immediate. */
const word = (
  opcode: number,
  dst: number,
  src: number,
  offset: number,
  imm: number,
): Uint8Array => {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  bytes[0] = opcode;
  bytes[1] = dst | (src << 4);
  view.setInt16(2, offset, true);
  view.setInt32(4, imm, true);
  return bytes;
};

/** Minimal sBPF ELF whose .text dispatches on the create_config discriminator. */
const buildElf = (): Uint8Array => {
  const text = new Uint8Array(5 * 8);
  [
    word(0x79, 3, 2, 0, 0),
    word(0x18, 4, 0, 0, 0x72f3cfc9),
    word(0x00, 0, 0, 0, 0xbd2f6f4b),
    word(0x1d, 3, 4, 5, 0),
    word(0x95, 0, 0, 0, 0),
  ].forEach((part, index) => text.set(part, index * 8));
  const shstrtab = new TextEncoder().encode("\0.text\0.shstrtab\0");
  const textOffset = 64;
  const shstrtabOffset = textOffset + text.length;
  const sectionHeaderOffset = shstrtabOffset + shstrtab.length;
  const bytes = new Uint8Array(sectionHeaderOffset + 3 * 64);
  const view = new DataView(bytes.buffer);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  view.setUint16(16, 3, true);
  view.setUint16(18, 263, true);
  view.setBigUint64(24, 0x100n, true);
  view.setBigUint64(40, BigInt(sectionHeaderOffset), true);
  view.setUint16(54, 56, true);
  view.setUint16(58, 64, true);
  view.setUint16(60, 3, true);
  view.setUint16(62, 2, true);
  bytes.set(text, textOffset);
  bytes.set(shstrtab, shstrtabOffset);
  const section = (
    index: number,
    name: number,
    address: number,
    offset: number,
    size: number,
  ): void => {
    const base = sectionHeaderOffset + index * 64;
    view.setUint32(base, name, true);
    view.setUint32(base + 4, 1, true);
    view.setBigUint64(base + 8, 6n, true);
    view.setBigUint64(base + 16, BigInt(address), true);
    view.setBigUint64(base + 24, BigInt(offset), true);
    view.setBigUint64(base + 32, BigInt(size), true);
  };
  section(1, 1, 0x100, textOffset, text.length);
  section(2, 7, 0, shstrtabOffset, shstrtab.length);
  return bytes;
};

it("writes a pinned handoff artifact with IDL-confirmed handler names", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-solana-handoff-"));
  const elf = buildElf();
  const elfPath = join(root, "program.so");
  await writeFile(elfPath, elf);
  const outDir = join(root, "out");
  const provider = new SolanaProgramProvider();
  const result = await provider.analyze({
    path: elfPath,
    out_dir: outDir,
    handoff: true,
    instruction_names: ["create_config", "nonexistent_ix"],
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const report = result.value;
  // The supplied name confirmed the candidate; the bogus name changed nothing.
  expect(report.handlers).toHaveLength(1);
  expect(report.handlers[0]?.name).toBe("create_config");

  const handoffDir = join(outDir, "handoff");
  const copied = await readFile(join(handoffDir, "program.so"));
  expect(createHash("sha256").update(copied).digest("hex")).toBe(
    report.artifact.sha256,
  );
  expect(Buffer.compare(copied, Buffer.from(elf))).toBe(0);

  const handoff = JSON.parse(
    await readFile(join(handoffDir, "handoff.json"), "utf8"),
  ) as SolanaHandoff;
  expect(handoff.elf_sha256).toBe(report.artifact.sha256);
  expect(handoff.entrypoint).toBe(report.elf.entrypoint);
  expect(handoff.handlers).toHaveLength(1);
  expect(handoff.dispatch.total_candidates).toBe(1);
  expect(handoff.source_analysis_path).toBe(
    join(outDir, "solana-analysis.json"),
  );

  const brief = await readFile(join(handoffDir, "HANDOFF.md"), "utf8");
  expect(brief).toContain("IDL-confirmed handlers (1");
  expect(brief).toContain("`create_config`");
  expect(brief).toContain(report.artifact.sha256);
  expect(brief).toContain("Ghidra/IDA");
  expect(brief).toContain("differential-verify");
});

it("leaves handler names null when no instruction names are supplied", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-solana-handoff-"));
  const elfPath = join(root, "program.so");
  await writeFile(elfPath, buildElf());
  const provider = new SolanaProgramProvider();
  const result = await provider.analyze({ path: elfPath });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.handlers[0]?.name).toBeNull();
});
