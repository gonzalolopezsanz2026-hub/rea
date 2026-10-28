# Linux BTF

`inspect_btf` / `inspect-btf` answers which types, struct layouts, prototypes,
variables and section records one selected Linux BPF Type Format artifact
declares, and which references remain unresolved. It reads the file without
loading a BPF program, attaching a probe, running a verifier, or touching the
live kernel. No BPF toolchain, debug package, or kernel headers are required.

```bash
rea inspect-btf /absolute/path/to/vmlinux.btf --json
```

MCP requires an absolute path and preserves the caller's selection:

```json
{
  "name": "inspect_btf",
  "arguments": { "path": "/artifacts/vmlinux.btf", "type_name": "task_struct" }
}
```

## Carriers

The selected bytes decide the carrier. A BTF magic admits a standalone blob,
such as a saved copy of `/sys/kernel/btf/vmlinux`. An ELF magic admits a section
lookup, defaulting to `.BTF`; pass `section` to select another name. The CLI
resolves relative paths against the working directory.

`.BTF.ext` is read from the same ELF when present. A standalone blob carries no
`.BTF.ext`, and the result says so rather than inventing records. When the ELF
also declares `.BTF.base`, split-BTF relocation is not performed: presence is
observed, but base type references stay unresolved and the reported ids are
file-local. `.BTF_ids` presence is observed only; its contents are not decoded.

## Observations

The inline Evidence result reports the artifact path, SHA-256, byte length,
carrier, selected section range, and header byte order, version, flags and
lengths. The `header.type` and `header.string` ranges are relative to the start
of the selected BTF blob. `strings` reports the string-section byte count,
NUL-terminated string count, and whether the required leading empty string is
present.

`types` pages the type inventory by 1-based id. Use `type_id` to return one id,
or `type_name` to return every exact match in id order; otherwise
`type_offset`/`type_limit` select a page. With `type_name`, `type_offset` still
counts matches rather than type ids. Duplicate names are expected and are not
collapsed. Each entry reports `kind`, `kind_flag`, name and name offset,
`vlen`, and the kind-specific payload:

- `int`: encoding names, bit offset and bit width.
- `ptr`, `typedef`, qualifiers, `func`, `func_proto`, `var`, `decl_tag` and
  `type_tag`: the referenced type id. `func` linkage is `static`, `global` or
  `extern`; `var` linkage is `static`, `global_allocated` or
  `global_extern`.
- `array`: element and index type ids plus the element count.
- `struct` and `union`: members with type id and bit offset. When `kind_flag`
  is set, the member offset word carries the bitfield size in its high byte.
- `enum` and `enum64`: names and values; `kind_flag` means signed.
- `fwd`: whether the forward declaration is a union.
- `datasec`: variable type id, byte offset and byte size.
- `float`: byte size.

`references` summarizes one level of types used anywhere in the decoded type
index, independent of the returned page, deduplicated by id. A reference outside the decoded type count is
`unresolved`; it is not treated as void. Paging is a delivery choice: omitted
ids still exist and still contribute to `types.total`.

## BTF.ext

When `.BTF.ext` is admitted, `ext` reports the header lengths and the func,
line and optional CO-RE subsection tables grouped by ELF section name. The
header subsection ranges are relative to the end of the ext header. The
header may be 24 bytes without the optional CO-RE tail or 32 bytes with it; both
are admitted. Records use each subsection's declared record size, so a future
wider record keeps its documented prefix.

Select `ext_section` to page records for one ELF section. `ext_offset` and
`ext_limit` page each subsection independently. Function records report the
instruction offset, function type id and name. Line records report file,
source-line text, line and column. CO-RE records report the access string,
numeric kind and documented kind name; they are reported, not applied.

## Unknowns and limits

An unknown kind ends the type scan and reports its id, observed kind value and
offset relative to the type section, plus the remaining undecoded byte count. A payload that does not fit the
type section is the same kind of partial observation; the reader does not guess
a payload length. A name offset outside the string section, a name without a
NUL terminator, or an exhausted retained-text budget yields a null name with a
limitation. References are still reported.

The selected file is limited to 64 MiB by default (512 MiB maximum). Type
paging defaults to 25 entries (100 maximum) and ext paging to 50 records per
subsection (200 maximum). Retained member, parameter, enumerator and
data-section entries share a 65,536-entry budget per result; a type that
exhausts it keeps its scalar facts and sets `facets_truncated`. Distinct
references are capped at 8,192, with `references_truncated` reporting the
omission. `coverage.status` is `partial` when the type section was not fully
decoded.

Malformed BTF headers, ranges outside the blob, overlapping type and string
sections, a missing `.BTF` section, a compressed `.BTF`, and exhausted input
budgets fail without partial success. A result does not prove that a type came
from a running kernel, that a program was loaded, or that a CO-RE relocation is
applicable to the current kernel.
