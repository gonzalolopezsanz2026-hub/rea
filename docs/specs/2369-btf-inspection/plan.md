# Implementation plan

1. Add the portable result and input schemas in `src/domain/native/btf.ts`,
   including the kind vocabulary, per-kind facets, paging selectors and the
   facet/reference budgets. Keep the schema strict and the defaults explicit.
2. Add `src/native/btf/BtfCarrier.ts` to select standalone BTF or an ELF
   section through the existing fixed-header and section-table primitives. It
   reuses the section-name decoder, refuses compressed `.BTF` storage, and
   reports `.BTF.base` and `.BTF_ids` presence without relocating anything.
3. Add `src/native/btf/BtfParser.ts` for the core blob. Index the type section
   in one pass, decode facets lazily for the requested page, resolve one-level
   references from the index, and keep unknown kinds, bad offsets, duplicate
   names and truncated payloads explicit.
4. Add `src/native/btf/BtfExtParser.ts` for `.BTF.ext`. Read the optional
   core-relo tail from `hdr_len`, walk each subsection's section table with its
   declared record size, and page records per ELF section.
5. Add `src/native/btf/BtfProvider.ts` beside the other portable providers. It
   performs one bounded stable read, parses in memory, and projects format,
   identity, cancellation and limit failures through the existing error algebra.
6. Wire the shared service in `src/application/binaryDiagnostics/BtfService.ts`
   and its port, then compose it in `src/composition/binaryDiagnostics.ts` and
   register it in `src/server/createServer.ts`.
7. Add the `inspect_btf` contract with truthful effects, the CLI command in
   `src/cli/binaryDiagnosticsCommands.ts`, and the canonical name in
   `src/cliCommandNames.ts`.
8. Document the operation in `docs/btf.md`, add it to the VitePress navigation,
   the README target table, and the native reference in the packaged skill.
9. Add the owned fixture builder and cover the parser, service, filesystem,
   MCP and CLI boundaries. A compiler-generated BPF object is not available on
   this host and is not claimed as coverage.
10. Run the focused tests, static checks and generated-document checks, then
    record the exact commands and unavailable coverage in the PR.

No new provider, execution path or target authority is introduced. The reader
is a format parser inside the existing binary-diagnostics lane.
