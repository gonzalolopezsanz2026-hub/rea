# Verification

## Environment

- Base revision: `06d1247` (`main`), dependencies from the lockfile with `npm ci`.
- Host: macOS on Apple silicon (Darwin), not Linux.
- Toolchain: Node.js `24.22.1` from `.nvmrc`, npm `11.19.1`.
- No compiler-generated `.BTF` object and no kernel `vmlinux` BTF were available
  on this host. All BTF/ELF inputs below are synthesized by
  `src/native/btf/Btf.fixture.ts` from the layouts in
  `include/uapi/linux/btf.h`.

## Commands and results

| Command                                                                                                                                                                                                                                                          | Observed result                                                                                     |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `npx tsc --noEmit -p tsconfig.json`                                                                                                                                                                                                                              | No diagnostics.                                                                                     |
| `npm run check:fast`                                                                                                                                                                                                                                             | `typecheck` and `lint` tasks successful (2 of 2).                                                   |
| `npm run test:focused -- src/native/btf/BtfParser.test.ts src/application/binaryDiagnostics/BtfService.test.ts tests/boundary/mcp/btfMcp.test.ts tests/acceptance/btfCli.test.ts tests/boundary/filesystem/btf.test.ts`                                          | 5 files, 34 tests passed.                                                                           |
| `npx vitest run tests/acceptance/tools/localToolContracts.test.ts`                                                                                                                                                                                               | 6 tests passed, including the `inspect_btf` NUL-path rejection through the advertised MCP contract. |
| `npx vitest run src/contracts/advertisedInputExamples.test.ts src/contracts/toolEffects.test.ts src/contracts/toolFamilies.test.ts src/contracts/compactInputSchema.test.ts src/contracts/compactOutputSchema.test.ts tests/boundary/mcp/serverIdentity.test.ts` | 6 files, 74 tests passed.                                                                           |
| `npx vitest run tests/boundary/filesystem/documentationFacts.test.ts tests/boundary/filesystem/productCatalog.test.ts`                                                                                                                                           | 2 files, 11 tests passed.                                                                           |
| `npm run docs:check`                                                                                                                                                                                                                                             | Generated-docs tasks successful (6 of 6); `readmeConsistency` 9 tests passed.                       |
| `npm run metadata:check`                                                                                                                                                                                                                                         | No drift reported.                                                                                  |
| `npm run format:check`                                                                                                                                                                                                                                           | All 6,239 matched files formatted.                                                                  |
| `npm run verify:test-discovery`                                                                                                                                                                                                                                  | All 2,721 test files discovered exactly once.                                                       |
| `npm run verify:module-boundaries`                                                                                                                                                                                                                               | Boundaries checked in 3,311 source files.                                                           |
| `npm run verify:architecture-guards`                                                                                                                                                                                                                             | Guards passed across 2,210 source files.                                                            |
| `npm run knip:production`                                                                                                                                                                                                                                        | 27 repository-wide advisory candidates; none from this change.                                      |
| `npm run lint:typed`                                                                                                                                                                                                                                             | 5,776 files, 0 errors, 3,849 advisory warnings.                                                     |
| `npm run jscpd`                                                                                                                                                                                                                                                  | 3.58% duplicated lines across 5,059 files.                                                          |
| `npm run scan:todos`                                                                                                                                                                                                                                             | No tech-debt markers found.                                                                         |

## What the tests cover

- `src/native/btf/BtfParser.test.ts` (15 tests): every released kind, struct
  and union members, bitfields, signed and unsigned enum64 values, vararg
  prototypes, tags, data sections, duplicate names, big-endian input, unknown
  kinds, truncated payloads, bad name offsets, unterminated names, unresolved
  references, ELF `.BTF`/`.BTF.ext` carriers, ext headers with and without the
  CO-RE tail, per-section ext paging, `.BTF.base` presence, a missing section,
  and compressed `.BTF` storage.
- `src/application/binaryDiagnostics/BtfService.test.ts` (7 tests): relative and
  extra arguments before reading, standalone and ELF Evidence subjects and
  locations, page and artifact-budget validation, header ranges outside the
  blob, and cancellation after the provider completes.
- `tests/boundary/mcp/btfMcp.test.ts` (5 tests): advertised annotations, a named
  type read, relative-path rejection, mutually exclusive id/name selection,
  ext records over MCP, and recovery after an invalid artifact.
- `tests/acceptance/btfCli.test.ts` (5 tests): named type output, relative CLI
  path resolution, ext paging, invalid input, missing section, and absence of
  artifact mutation.
- `tests/boundary/filesystem/btf.test.ts` (2 tests): directory, symlink,
  malformed, missing and non-regular selections; read-budget and cancellation
  failures.

## Not verified

- **Compiler-generated BTF**: Apple clang on this host has no BPF target and
  Docker was not running, so no `clang -target bpf -g` object was produced. The
  fixture encoder mirrors the header layouts but is not compiler output.
- **Real kernel BTF**: no `vmlinux` or `/sys/kernel/btf/*` artifact was
  available. No claim is made about a specific kernel version, BTF feature set,
  or split-BTF base layout.
- **BPF runtime behavior**: loading, probing, verifying and CO-RE relocation are
  out of scope and were not performed. CO-RE records are decoded, not applied.
- **Other platforms**: the checks above ran only on macOS.
- **Full repository suite**: `npm run check:pr` and the complete test suite were
  not run; only the focused suites and static gates listed above were executed.
