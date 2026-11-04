# regent-sdk protobuf schema

| File | Content | Edited |
|---|---|---|
| `regent/v1/model.proto` | Mirror of `RegentTaskResult` and every type it contains | **generated**, never by hand |
| `regent/v1/protogen.lock.json` | Field numbers of the generated messages | generated, commit it |
| `regent/v1/reporting.proto` | `Reporting` service (agents → collector) | by hand |
| `../src/proto/conv/*.rs` | Rust ⇄ protobuf conversions and round-trip tests | generated |

## Why

The serde layout of `RegentTaskResult` changes between regent-sdk versions; its
protobuf form does not: field numbers are stable, and Google's protobuf runtime
keeps the fields a reader does not know and writes them back unchanged. Agents and
collectors built on different regent-sdk versions can therefore exchange outcomes.

## Regenerating

Whenever a type reachable from `RegentTaskResult` changes (new attribute, new
variant, new field…), from the regent-sdk root:

```bash
cargo run --manifest-path tools/protogen/Cargo.toml
cargo test -F proto --lib proto     # one round-trip test per generated type
```

and commit `model.proto`, `protogen.lock.json` and `src/proto/conv/` with the
change. The generator also adds a `mod proto_conv;` line (feature `proto`) to
modules defining mirrored types, so conversions can read private fields.

## Compatibility rules (enforced by the lock file)

- A field or variant keeps its number forever; a removed one becomes `reserved`
  (and gets its old number back if it reappears under the same name).
- A type must keep its representation (message / oneof / transparent newtype);
  the generator refuses a change (e.g. a newtype becoming a struct) since it
  breaks the wire format: give the new shape a new type name instead.
- Renaming a field or variant is a removal plus an addition (new number).

## Mapping

| Rust | protobuf |
|---|---|
| struct (named fields, 2+ tuple fields, unit) | message (`f0`, `f1`… for tuple fields) |
| tuple struct with one scalar/message field | its inner type (transparent) |
| enum (every enum, even without data) | message with `oneof variant_kind`; unit variants carry `Unit`, one-field tuple variants carry the field, others a `<Enum>_<Variant>` message |
| generic type | one message per use: `Parameter<String>` → `Parameter_String` |
| `Option<T>` | `optional` / message presence |
| `Vec<T>`, `BTreeSet<T>` | `repeated` |
| `BTreeMap`, `HashMap` | `map` |
| nested containers | wrappers `OptionOf_*`, `ListOf_*`, `SetOf_*`, `MapOf_*_*` |
| `Result<T, E>` field | `oneof <field> { <field>_ok; <field>_err }` |
| `String`, `PathBuf`, `IpAddr` | `string` |
| `u8`, `u16`, `u32` / `u64`, `usize` | `uint32` / `uint64` |
| `chrono::DateTime<Utc>` / `std::time::Duration` | `Timestamp` / `RustDuration` |

Converting to Rust types, a variant unknown to the reader (newer sender) becomes
`Remediation::None(..)` or `RegentError::AnyOtherError(..)`; anything else
inconsistent is a `ProtoError`. To pass data on without loss, forward the protobuf
message, not the converted Rust value.

## Toolchain

`protoc` must be **exactly** the version matching the `protobuf` crate pinned in
`Cargo.toml` (`=4.36.1-release` ⇒ protoc 36.1): `protobuf-codegen` refuses any
other. CI, release workflows and container builds must install that version.
