import {
  MAX_INSPECT_BTF_NAME_BYTES,
  MAX_INSPECT_BTF_NAME_TEXT_BYTES,
} from "../../domain/native/btf.js";

/**
 * Resolve BTF names from one string section.
 *
 * A missing terminator, an offset outside the section, or an exhausted
 * retained-text budget yields null. The caller keeps the reference and adds an
 * explicit limitation; it never receives a silently shortened name.
 */
export class BtfStrings {
  readonly #bytes: Buffer;
  readonly #start: number;
  readonly #length: number;
  readonly #limitations: Set<string>;
  #remaining: number;
  #truncated = 0;

  constructor(
    bytes: Buffer,
    start: number,
    length: number,
    limitations: Set<string>,
  ) {
    this.#bytes = bytes;
    this.#start = start;
    this.#length = length;
    this.#limitations = limitations;
    this.#remaining = MAX_INSPECT_BTF_NAME_TEXT_BYTES;
  }

  get length(): number {
    return this.#length;
  }

  /** Names replaced by null because the retained-text budget ran out. */
  get truncated(): number {
    return this.#truncated;
  }

  resolve(offset: number): string | null {
    if (offset === 0) return "";
    if (offset >= this.#length) {
      this.#limitations.add(
        "A BTF name offset is outside the string section; the name is unknown.",
      );
      return null;
    }
    const from = this.#start + offset;
    const end = this.#bytes.indexOf(0, from);
    const withinSection =
      end >= 0 && end - this.#start < this.#length ? end : -1;
    if (
      withinSection < 0 ||
      withinSection - from > MAX_INSPECT_BTF_NAME_BYTES
    ) {
      this.#truncated += 1;
      this.#limitations.add(
        `A BTF name is not NUL-terminated within the ${String(MAX_INSPECT_BTF_NAME_BYTES)}-byte retained name budget; it is unknown.`,
      );
      return null;
    }
    const bytes = withinSection - from;
    if (bytes > this.#remaining) {
      this.#truncated += 1;
      return null;
    }
    this.#remaining -= bytes;
    return this.#bytes.toString("latin1", from, withinSection);
  }

  /** Exact-name comparison without charging the retained-name budget. */
  equals(offset: number, target: Buffer): boolean {
    if (offset === 0) return target.length === 0;
    if (offset >= this.#length) return false;
    const from = this.#start + offset;
    if (target.length > this.#length - offset - 1) return false;
    return (
      this.#bytes.compare(
        target,
        0,
        target.length,
        from,
        from + target.length,
      ) === 0 && this.#bytes[from + target.length] === 0
    );
  }
}
