# Linux BTF inspection

Issue: https://github.com/morluto/rea/issues/2369

## Outcome

`inspect_btf` / `inspect-btf` reads one selected BTF blob and returns its type,
string and BTF.ext facts without loading a program, attaching a probe, invoking
a verifier or reading live kernel state. The reader admits a standalone BTF blob
and an ELF image that carries a `.BTF` section. `.BTF.ext` is read from the same
ELF when present.

The analyst question is: which named types, struct layouts, prototypes,
variables and section records does this kernel artifact declare, and which
references remain unresolved. Ordinary ELF section inventory cannot answer it
because the type and string sections are an indexed graph, not a name list.

## Requirements

- Detect the carrier from the selected bytes: the BTF magic admits a standalone
  blob, the ELF magic admits a section lookup, and anything else is refused
  instead of guessed. Name the exact section selected.
- Preserve source identity: absolute path, SHA-256, byte length, carrier, and
  the file range of the selected section. A standalone blob reports the range of
  its own header through the end of its string section.
- Decode the header exactly: magic, byte order derived from the magic encoding,
  version, flags, header length, and type/string offsets relative to the end of
  the header. Offsets and lengths that leave the artifact fail; they do not
  produce a second, repaired interpretation.
- Decode every released kind 1 through 19 with its kind-specific payload, and
  keep kind 0 and kinds above 19 explicit. An unknown kind is an unsupported
  extension: report its type id, observed kind value and byte offset, stop the
  type scan, and report the remaining bytes as undecoded. Do not guess a payload
  length.
- Resolve type and string references without inventing values. A name offset
  outside the string section, or a string without a NUL terminator inside the
  admitted name budget, yields a null name plus an explicit limitation. A type
  reference outside the decoded type count is unresolved, not void and not
  absent.
- Keep the 16-bit vlen, 5-bit kind and kind_flag decoding from
  `include/uapi/linux/btf.h`. The published prose describes a wider vlen and
  kind field; the header macros are the implementation contract. Record that
  discrepancy in the source comment rather than adapting either interpretation
  at runtime.
- Preserve `kind_flag` semantics per kind: struct/union bitfield size and bit
  offset, signed enum and enum64 values, struct versus union forward
  declarations, and attribute-list decl/type tags.
- Decode `.BTF.ext` func, line and optional CO-RE subsections. Records use the
  subsection's declared record size, must fit their declared section count, and
  keep the known prefix when a future record is wider. Line numbers and columns
  use the documented `line_col` split. CO-RE kind names are reported only for
  the documented range and stay numeric with `unknown` otherwise.
- Page the type inventory by 1-based id and the ext records by ELF section. A
  selected type id or exact name returns that selection; duplicate names return
  every match in id order. Paging is a delivery choice, not evidence that the
  omitted ids do not exist.
- Bound every decode to the selected artifact and its declared sections. Output
  growth is bounded by a per-result facet-entry budget; a page that exhausts it
  keeps each remaining type's scalar facts and marks the entry and coverage as
  truncated. References are deduplicated and capped with explicit coverage.
- Report split BTF honestly. `.BTF.base` and `.BTF_ids` presence on the ELF is
  observed, but base relocation is not performed and base type references stay
  unresolved. File-local ids are labelled as such.
- Report observed, derived and inferred facts separately. A header value is
  observed. A struct member bit offset is observed. "This is a kernel type" is
  not proven by the container alone.

## Acceptance and limits

The owned fixture builder encodes every released kind, a bitfield struct,
signed and unsigned enum64 values, a vararg prototype, a declarative tag, a
type tag chain, a typed data section, duplicate type names, a big-endian blob,
an unknown kind, out-of-range name and type references, an unterminated string,
a truncated type payload, a `.BTF.ext` header with and without the optional
CO-RE tail, an ELF section carrier, and a compressed `.BTF` section. CLI, MCP
and filesystem boundary tests exercise the same service with the production
contracts. The builder is derived from `include/uapi/linux/btf.h`, not from a
compiler, so a real compiler-generated object and a real kernel `vmlinux` BTF
remain unverified by this change.

No execution, injection, network, kernel or filesystem mutation authority is
introduced. The operation reads one selected regular file.
