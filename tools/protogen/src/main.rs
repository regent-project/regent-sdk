//! regent-protogen: generates the protobuf mirror of regent-sdk's outcome types.
//!
//! Run from the regent-sdk root:
//!
//! ```text
//! cargo run --manifest-path tools/protogen/Cargo.toml
//! ```
//!
//! It parses `src/**/*.rs`, walks every type reachable from the roots
//! ([`ROOTS`]) and writes:
//!
//! - `proto/regent/v1/model.proto`: one message per Rust type;
//! - `src/proto/conv/<module>.rs`: conversions (Rust <-> protobuf) and
//!   round-trip tests, included as a child module of the module defining the
//!   types (so they can read private fields), through a
//!   `#[cfg(feature = "proto")] #[path = ...] mod proto_conv;` line that the
//!   tool adds to that module when missing;
//! - `proto/regent/v1/protogen.lock.json`: field numbers. Numbers are never
//!   reused or renumbered: a removed field keeps its number as `reserved`.
//!
//! Mapping (see also proto/README.md):
//!
//! - struct with named fields / tuple struct with 2+ fields / unit struct →
//!   message (tuple fields are named `f0`, `f1`, …);
//! - tuple struct with exactly one field whose type is "singular" (scalar or
//!   message) → *transparent*: represented as its inner type;
//! - every enum → message with a `oneof regent_variant`; unit variants carry
//!   `Unit`, single-field tuple variants carry the field's type, other variants a
//!   message named `<Enum>_<Variant>`;
//! - generics are monomorphized: `Parameter<String>` → `Parameter_String`;
//! - `Option<T>` → `optional` (or message presence); `Vec`/`BTreeSet` →
//!   `repeated`; `BTreeMap`/`HashMap` → `map`; nested containers (e.g.
//!   `Option<Vec<T>>` as a oneof case or list item) → wrapper messages
//!   `OptionOf_*`, `ListOf_*`, `SetOf_*`, `MapOf_*_*`;
//! - `Result<T, E>` (struct fields only) → `oneof <field> { <field>_ok; <field>_err }`;
//! - `String`, `PathBuf`, `IpAddr` → string; `u8`/`u16`/`u32` → uint32;
//!   `u64`/`usize` → uint64; `std::time::Duration` → `RustDuration`;
//!   `chrono::DateTime<Utc>` → `Timestamp`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Types the mirror starts from.
const ROOTS: &[&str] = &["RegentTaskResult"];

/// Types whose decoding falls back to a value of the same type when the message
/// holds a variant this SDK does not know (sent by a newer regent-sdk). `{}` is
/// replaced by the name of the unknown type.
const FALLBACKS: &[(&str, &str)] = &[
    (
        "Remediation",
        "Remediation::None(::std::format!(\"unknown remediation from a newer regent-sdk ({})\", unknown))",
    ),
    (
        "RegentError",
        "RegentError::AnyOtherError(::std::format!(\"unknown error from a newer regent-sdk ({})\", unknown))",
    ),
];

const RUST_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen",
];

fn main() {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if let Err(error) = run(&root) {
        eprintln!("regent-protogen: {error}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Source model
// ---------------------------------------------------------------------------

struct Def {
    name: String,
    /// Source file, relative to the SDK root (e.g. `src/task.rs`).
    file: PathBuf,
    /// Module path segments (e.g. `["state", "compliance"]`).
    module: Vec<String>,
    generics: Vec<String>,
    /// Traits listed in `#[derive(..)]`
    derives: Vec<String>,
    item: DefItem,
}

enum DefItem {
    Struct(syn::ItemStruct),
    Enum(syn::ItemEnum),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Prim {
    String,
    Bool,
    U8,
    U16,
    U32,
    U64,
    Usize,
    I32,
    I64,
    F32,
    F64,
    PathBuf,
    IpAddr,
    Duration,
    DateTime,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Ty {
    Prim(Prim),
    Option(Box<Ty>),
    Vec(Box<Ty>),
    Set(Box<Ty>),
    Map(Box<Ty>, Box<Ty>),
    Box(Box<Ty>),
    Result(Box<Ty>, Box<Ty>),
    /// Index into `Gen::defs`, plus generic arguments.
    Named(usize, Vec<Ty>),
}

struct Field {
    /// Rust accessor (`name` or `0`).
    rust: String,
    /// Field name in the proto message.
    proto: String,
    ty: Ty,
    cfgs: Vec<String>,
}

enum VariantKind {
    Unit,
    Tuple(Vec<Field>),
    Struct(Vec<Field>),
}

struct Variant {
    name: String,
    case: String,
    kind: VariantKind,
    cfgs: Vec<String>,
}

enum Repr {
    Message { fields: Vec<Field>, tuple: bool, unit: bool },
    Transparent(Ty),
    Enum(Vec<Variant>),
}

// ---------------------------------------------------------------------------
// Lock file
// ---------------------------------------------------------------------------

#[derive(Default, Serialize, Deserialize)]
struct Lock {
    version: u32,
    /// proto message name → entry
    messages: BTreeMap<String, LockEntry>,
}

#[derive(Default, Serialize, Deserialize, Clone)]
struct LockEntry {
    /// "message" | "oneof" | "transparent"
    repr: String,
    #[serde(default)]
    fields: BTreeMap<String, u32>,
    /// fields removed from the Rust type: their numbers stay reserved
    #[serde(default)]
    retired: BTreeMap<String, u32>,
}

impl LockEntry {
    fn number(&mut self, name: &str) -> u32 {
        if let Some(number) = self.fields.get(name) {
            return *number;
        }
        if let Some(number) = self.retired.remove(name) {
            self.fields.insert(name.to_string(), number);
            return number;
        }
        let next = self
            .fields
            .values()
            .chain(self.retired.values())
            .copied()
            .max()
            .unwrap_or(0)
            + 1;
        let next = if (19000..20000).contains(&next) { 20000 } else { next };
        self.fields.insert(name.to_string(), next);
        next
    }
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

struct Inst {
    def: usize,
    args: Vec<Ty>,
    proto_name: String,
    repr: Repr,
}

struct Gen {
    defs: Vec<Def>,
    by_name: HashMap<String, Vec<usize>>,
    insts: Vec<Inst>,
    inst_index: HashMap<(usize, Vec<Ty>), usize>,
    /// wrapper message name → wrapped type
    wrappers: BTreeMap<String, Ty>,
    lock: Lock,
    used: BTreeMap<String, BTreeSet<String>>,
}

fn run(root: &Path) -> Result<(), String> {
    let src = root.join("src");
    let mut defs = Vec::new();
    collect_defs(root, &src, &mut defs)?;
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, def) in defs.iter().enumerate() {
        by_name.entry(def.name.clone()).or_default().push(index);
    }

    let lock_path = root.join("proto/regent/v1/protogen.lock.json");
    let lock: Lock = match std::fs::read_to_string(&lock_path) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", lock_path.display()))?,
        Err(_) => Lock { version: 1, ..Default::default() },
    };

    let mut generator = Gen {
        defs,
        by_name,
        insts: Vec::new(),
        inst_index: HashMap::new(),
        wrappers: BTreeMap::new(),
        lock,
        used: BTreeMap::new(),
    };

    for root_name in ROOTS {
        let index = generator.resolve(root_name, None)?;
        generator.instantiate(index, Vec::new())?;
    }
    generator.check_cycles()?;

    let proto = generator.emit_proto()?;
    write_if_changed(&root.join("proto/regent/v1/model.proto"), &proto)?;

    let conv_dir = root.join("src/proto/conv");
    std::fs::create_dir_all(&conv_dir).map_err(|e| e.to_string())?;
    let mut written = BTreeSet::new();
    for (file_name, (source_file, content)) in generator.emit_rust()? {
        write_if_changed(&conv_dir.join(&file_name), &content)?;
        ensure_mod_line(root, &source_file, &file_name)?;
        written.insert(file_name);
    }
    // remove stale generated files
    for entry in std::fs::read_dir(&conv_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".rs") && !written.contains(&name) {
            std::fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
            eprintln!("removed stale {}", entry.path().display());
        }
    }

    generator.retire_unused();
    let raw = serde_json::to_string_pretty(&generator.lock).map_err(|e| e.to_string())? + "\n";
    write_if_changed(&lock_path, &raw)?;

    eprintln!(
        "regent-protogen: {} messages ({} wrappers), {} conversion files",
        generator.insts.iter().filter(|i| !matches!(i.repr, Repr::Transparent(_))).count(),
        generator.wrappers.len(),
        written.len()
    );
    Ok(())
}

fn write_if_changed(path: &Path, content: &str) -> Result<(), String> {
    if std::fs::read_to_string(path).ok().as_deref() == Some(content) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, content).map_err(|e| format!("{}: {e}", path.display()))?;
    eprintln!("wrote {}", path.display());
    Ok(())
}

fn collect_defs(root: &Path, dir: &Path, defs: &mut Vec<Def>) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).unwrap().to_path_buf();
        if relative.starts_with("src/proto") {
            continue;
        }
        if path.is_dir() {
            collect_defs(root, &path, defs)?;
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let file = syn::parse_file(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        let module = module_path(&relative);
        for item in file.items {
            let (name, generics, derives, item) = match item {
                syn::Item::Struct(s) => (s.ident.to_string(), generic_names(&s.generics), derive_names(&s.attrs), DefItem::Struct(s)),
                syn::Item::Enum(e) => (e.ident.to_string(), generic_names(&e.generics), derive_names(&e.attrs), DefItem::Enum(e)),
                _ => continue,
            };
            defs.push(Def { name, file: relative.clone(), module: module.clone(), generics, derives, item });
        }
    }
    Ok(())
}

fn module_path(relative: &Path) -> Vec<String> {
    let mut parts: Vec<String> = relative
        .strip_prefix("src")
        .unwrap()
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    let last = parts.pop().unwrap();
    let stem = last.trim_end_matches(".rs").to_string();
    if stem != "mod" && stem != "lib" {
        parts.push(stem);
    }
    parts
}

fn generic_names(generics: &syn::Generics) -> Vec<String> {
    generics
        .params
        .iter()
        .filter_map(|p| match p {
            syn::GenericParam::Type(t) => Some(t.ident.to_string()),
            _ => None,
        })
        .collect()
}

fn derive_names(attrs: &[syn::Attribute]) -> Vec<String> {
    let mut out = Vec::new();
    for attr in attrs.iter().filter(|a| a.path().is_ident("derive")) {
        let _ = attr.parse_nested_meta(|meta| {
            if let Some(last) = meta.path.segments.last() {
                out.push(last.ident.to_string());
            }
            Ok(())
        });
    }
    out
}

fn cfg_attrs(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("cfg"))
        .map(|a| quote::quote!(#a).to_string())
        .collect()
}

fn snake(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            let prev_lower = i > 0 && (chars[i - 1].is_lowercase() || chars[i - 1].is_ascii_digit());
            let next_lower = i + 1 < chars.len() && chars[i + 1].is_lowercase();
            let prev_upper = i > 0 && chars[i - 1].is_uppercase();
            if i > 0 && (prev_lower || (prev_upper && next_lower)) {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(*c);
        }
    }
    out
}

fn proto_field_name(name: &str) -> String {
    let name = name.trim_start_matches("r#");
    if RUST_KEYWORDS.contains(&name) || name == "variant_kind" {
        format!("{name}_")
    } else {
        name.to_string()
    }
}

impl Gen {
    fn resolve(&self, name: &str, from_file: Option<&Path>) -> Result<usize, String> {
        let candidates = self
            .by_name
            .get(name)
            .ok_or_else(|| format!("type `{name}` not found in src/ (used in {from_file:?})"))?;
        if candidates.len() == 1 {
            return Ok(candidates[0]);
        }
        if let Some(file) = from_file {
            let same: Vec<_> = candidates.iter().filter(|i| self.defs[**i].file == file).collect();
            if same.len() == 1 {
                return Ok(*same[0]);
            }
            let dir = file.parent();
            let near: Vec<_> = candidates
                .iter()
                .filter(|i| self.defs[**i].file.parent() == dir)
                .collect();
            if near.len() == 1 {
                return Ok(*near[0]);
            }
        }
        Err(format!(
            "type `{name}` is ambiguous (used in {from_file:?}): defined in {:?}",
            candidates.iter().map(|i| &self.defs[*i].file).collect::<Vec<_>>()
        ))
    }

    fn convert_type(&mut self, ty: &syn::Type, file: &Path, subst: &HashMap<String, Ty>) -> Result<Ty, String> {
        match ty {
            syn::Type::Paren(p) => self.convert_type(&p.elem, file, subst),
            syn::Type::Group(g) => self.convert_type(&g.elem, file, subst),
            syn::Type::Path(tp) => {
                let segment = tp.path.segments.last().ok_or("empty path")?;
                let ident = segment.ident.to_string();
                let full: Vec<String> = tp.path.segments.iter().map(|s| s.ident.to_string()).collect();
                let args: Vec<&syn::Type> = match &segment.arguments {
                    syn::PathArguments::AngleBracketed(a) => a
                        .args
                        .iter()
                        .filter_map(|a| match a {
                            syn::GenericArgument::Type(t) => Some(t),
                            _ => None,
                        })
                        .collect(),
                    _ => Vec::new(),
                };
                if args.is_empty() {
                    if let Some(t) = subst.get(&ident) {
                        return Ok(t.clone());
                    }
                }
                let arg = |i: usize, g: &mut Gen| -> Result<Ty, String> {
                    let t = args.get(i).ok_or_else(|| format!("`{ident}` misses a type argument in {}", file.display()))?;
                    g.convert_type(t, file, subst)
                };
                let prim = |p: Prim| Ok(Ty::Prim(p));
                match ident.as_str() {
                    "String" => prim(Prim::String),
                    "bool" => prim(Prim::Bool),
                    "u8" => prim(Prim::U8),
                    "u16" => prim(Prim::U16),
                    "u32" => prim(Prim::U32),
                    "u64" => prim(Prim::U64),
                    "usize" => prim(Prim::Usize),
                    "i32" => prim(Prim::I32),
                    "i64" => prim(Prim::I64),
                    "f32" => prim(Prim::F32),
                    "f64" => prim(Prim::F64),
                    "PathBuf" => prim(Prim::PathBuf),
                    "IpAddr" => prim(Prim::IpAddr),
                    "Duration" if !full.iter().any(|s| s == "chrono") => prim(Prim::Duration),
                    "DateTime" => prim(Prim::DateTime),
                    "Option" => Ok(Ty::Option(Box::new(arg(0, self)?))),
                    "Vec" => Ok(Ty::Vec(Box::new(arg(0, self)?))),
                    "BTreeSet" | "HashSet" => Ok(Ty::Set(Box::new(arg(0, self)?))),
                    "BTreeMap" | "HashMap" => {
                        let k = arg(0, self)?;
                        let v = arg(1, self)?;
                        Ok(Ty::Map(Box::new(k), Box::new(v)))
                    }
                    "Box" => Ok(Ty::Box(Box::new(arg(0, self)?))),
                    "Result" => {
                        let t = arg(0, self)?;
                        let e = arg(1, self)?;
                        Ok(Ty::Result(Box::new(t), Box::new(e)))
                    }
                    _ => {
                        let index = self.resolve(&ident, Some(file))?;
                        let mut converted = Vec::new();
                        for i in 0..args.len() {
                            converted.push(arg(i, self)?);
                        }
                        if converted.len() != self.defs[index].generics.len() {
                            return Err(format!("`{ident}`: wrong number of type arguments in {}", file.display()));
                        }
                        self.instantiate(index, converted.clone())?;
                        Ok(Ty::Named(index, converted))
                    }
                }
            }
            other => Err(format!(
                "unsupported type `{}` in {}",
                quote::quote!(#other),
                file.display()
            )),
        }
    }

    fn name_of(&self, ty: &Ty) -> String {
        match ty {
            Ty::Prim(p) => format!("{p:?}"),
            Ty::Option(t) => format!("OptionOf_{}", self.name_of(t)),
            Ty::Vec(t) => format!("ListOf_{}", self.name_of(t)),
            Ty::Set(t) => format!("SetOf_{}", self.name_of(t)),
            Ty::Map(k, v) => format!("MapOf_{}_{}", self.name_of(k), self.name_of(v)),
            Ty::Box(t) => self.name_of(t),
            Ty::Result(t, e) => format!("ResultOf_{}_{}", self.name_of(t), self.name_of(e)),
            Ty::Named(index, args) => {
                let mut name = self.defs[*index].name.clone();
                for a in args {
                    name.push('_');
                    name.push_str(&self.name_of(a));
                }
                name
            }
        }
    }

    fn instantiate(&mut self, def: usize, args: Vec<Ty>) -> Result<usize, String> {
        if let Some(i) = self.inst_index.get(&(def, args.clone())) {
            return Ok(*i);
        }
        let proto_name = self.name_of(&Ty::Named(def, args.clone()));
        let index = self.insts.len();
        // placeholder to stop recursion
        self.insts.push(Inst {
            def,
            args: args.clone(),
            proto_name: proto_name.clone(),
            repr: Repr::Message { fields: Vec::new(), tuple: false, unit: true },
        });
        self.inst_index.insert((def, args.clone()), index);

        let subst: HashMap<String, Ty> = self.defs[def]
            .generics
            .iter()
            .cloned()
            .zip(args.iter().cloned())
            .collect();
        let file = self.defs[def].file.clone();
        let repr = match &self.defs[def].item {
            DefItem::Struct(s) => {
                let s = s.clone();
                let fields = self.convert_fields(&s.fields, &file, &subst)?;
                match &s.fields {
                    syn::Fields::Unnamed(_) if fields.len() == 1 && self.is_singular(&fields[0].ty) => {
                        Repr::Transparent(fields.into_iter().next().unwrap().ty)
                    }
                    syn::Fields::Unnamed(_) => Repr::Message { fields, tuple: true, unit: false },
                    syn::Fields::Unit => Repr::Message { fields, tuple: false, unit: true },
                    syn::Fields::Named(_) => Repr::Message { fields, tuple: false, unit: false },
                }
            }
            DefItem::Enum(e) => {
                let e = e.clone();
                let mut variants = Vec::new();
                for v in &e.variants {
                    let fields = self.convert_fields(&v.fields, &file, &subst)?;
                    let kind = match &v.fields {
                        syn::Fields::Unit => VariantKind::Unit,
                        syn::Fields::Unnamed(_) => VariantKind::Tuple(fields),
                        syn::Fields::Named(_) => VariantKind::Struct(fields),
                    };
                    let name = v.ident.to_string();
                    variants.push(Variant {
                        case: proto_field_name(&snake(&name)),
                        name,
                        kind,
                        cfgs: cfg_attrs(&v.attrs),
                    });
                }
                Repr::Enum(variants)
            }
        };
        self.insts[index].repr = repr;
        Ok(index)
    }

    fn convert_fields(&mut self, fields: &syn::Fields, file: &Path, subst: &HashMap<String, Ty>) -> Result<Vec<Field>, String> {
        let mut out = Vec::new();
        for (i, f) in fields.iter().enumerate() {
            let ty = self.convert_type(&f.ty, file, subst)?;
            let (rust, proto) = match &f.ident {
                Some(ident) => {
                    let name = ident.to_string();
                    (name.clone(), proto_field_name(&name))
                }
                None => (i.to_string(), format!("f{i}")),
            };
            out.push(Field { rust, proto, ty, cfgs: cfg_attrs(&f.attrs) });
        }
        Ok(out)
    }

    fn inst_of(&self, def: usize, args: &[Ty]) -> &Inst {
        &self.insts[self.inst_index[&(def, args.to_vec())]]
    }

    fn transparent_inner(&self, ty: &Ty) -> Option<Ty> {
        match ty {
            Ty::Named(def, args) => match &self.inst_of(*def, args).repr {
                Repr::Transparent(inner) => Some(inner.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    /// Representable as a single proto value (scalar or message), not a container.
    fn is_singular(&self, ty: &Ty) -> bool {
        match ty {
            Ty::Prim(_) => true,
            Ty::Box(t) => self.is_singular(t),
            Ty::Named(def, args) => match self.inst_index.get(&(*def, args.clone())) {
                Some(i) => match &self.insts[*i].repr {
                    Repr::Transparent(inner) => self.is_singular(inner),
                    _ => true,
                },
                None => true,
            },
            _ => false,
        }
    }

    /// Represented by a proto message (has presence, read through a View).
    fn is_message(&self, ty: &Ty) -> bool {
        match ty {
            Ty::Prim(Prim::Duration | Prim::DateTime) => true,
            Ty::Prim(_) => false,
            Ty::Box(t) => self.is_message(t),
            Ty::Named(..) => match self.transparent_inner(ty) {
                Some(inner) => self.is_message(&inner),
                None => true,
            },
            Ty::Result(..) => panic!("Result outside a struct field"),
            _ => true, // wrappers
        }
    }

    /// Proto type of a value of `ty` (registering wrappers when needed).
    fn proto_type(&mut self, ty: &Ty) -> String {
        match ty {
            Ty::Prim(p) => match p {
                Prim::String | Prim::PathBuf | Prim::IpAddr => "string",
                Prim::Bool => "bool",
                Prim::U8 | Prim::U16 | Prim::U32 => "uint32",
                Prim::U64 | Prim::Usize => "uint64",
                Prim::I32 => "int32",
                Prim::I64 => "int64",
                Prim::F32 => "float",
                Prim::F64 => "double",
                Prim::Duration => "RustDuration",
                Prim::DateTime => "Timestamp",
            }
            .to_string(),
            Ty::Box(t) => self.proto_type(t),
            Ty::Named(def, args) => match self.transparent_inner(ty) {
                Some(inner) => self.proto_type(&inner),
                None => self.inst_of(*def, args).proto_name.clone(),
            },
            Ty::Result(..) => panic!("Result outside a struct field"),
            other => {
                let name = self.name_of(other);
                if !self.wrappers.contains_key(&name) {
                    self.wrappers.insert(name.clone(), other.clone());
                    // register nested wrappers
                    match other {
                        Ty::Option(t) | Ty::Vec(t) | Ty::Set(t) => {
                            self.proto_type(t);
                        }
                        Ty::Map(k, v) => {
                            self.proto_type(k);
                            self.proto_type(v);
                        }
                        _ => {}
                    }
                }
                name
            }
        }
    }

    /// Rust type of the proto value read for `ty` (the `In` of FromProtoValue).
    fn view_type(&mut self, ty: &Ty) -> String {
        if self.is_message(ty) {
            return format!("::protobuf::View<'a, crate::proto::{}>", self.proto_type(ty));
        }
        match self.proto_type(ty).as_str() {
            "string" => "&'a ::protobuf::ProtoStr".to_string(),
            "uint32" => "u32".into(),
            "uint64" => "u64".into(),
            "int32" => "i32".into(),
            "int64" => "i64".into(),
            "float" => "f32".into(),
            "double" => "f64".into(),
            "bool" => "bool".into(),
            other => panic!("no view type for {other}"),
        }
    }

    /// Rust type of the proto value written for `ty` (the `Out` of IntoProtoValue).
    fn out_type(&mut self, ty: &Ty) -> String {
        if self.is_message(ty) {
            return format!("crate::proto::{}", self.proto_type(ty));
        }
        match self.proto_type(ty).as_str() {
            "string" => "::std::string::String".to_string(),
            "uint32" => "u32".into(),
            "uint64" => "u64".into(),
            "int32" => "i32".into(),
            "int64" => "i64".into(),
            "float" => "f32".into(),
            "double" => "f64".into(),
            "bool" => "bool".into(),
            other => panic!("no out type for {other}"),
        }
    }

    // ---------------- conversion expressions ----------------

    /// `e`: expression of type `&T` → expression of the owned proto value.
    fn to_val(&mut self, ty: &Ty, e: &str, depth: usize) -> String {
        let x = format!("x{depth}");
        let k = format!("k{depth}");
        match ty {
            Ty::Prim(p) => match p {
                Prim::String => format!("::std::clone::Clone::clone({e})"),
                Prim::PathBuf => format!("({e}).to_string_lossy().into_owned()"),
                Prim::IpAddr => format!("::std::string::ToString::to_string({e})"),
                Prim::Bool | Prim::U32 | Prim::U64 | Prim::I32 | Prim::I64 | Prim::F32 | Prim::F64 => format!("*({e})"),
                Prim::U8 | Prim::U16 => format!("u32::from(*({e}))"),
                Prim::Usize => format!("(*({e}) as u64)"),
                Prim::Duration => format!("crate::proto::convert::duration_to_proto({e})"),
                Prim::DateTime => format!("crate::proto::convert::timestamp_to_proto({e})"),
            },
            Ty::Named(..) => format!("crate::proto::convert::IntoProtoValue::into_proto_value({e})"),
            Ty::Box(t) => self.to_val(t, &format!("&**({e})"), depth),
            Ty::Result(..) => panic!("Result outside a struct field"),
            Ty::Option(t) => {
                let w = self.proto_type(ty);
                let inner = self.to_val(t, &x, depth + 1);
                format!("{{ let mut w = crate::proto::{w}::new(); if let ::std::option::Option::Some({x}) = {e} {{ w.set_value({inner}); }} w }}")
            }
            Ty::Vec(t) | Ty::Set(t) => {
                let w = self.proto_type(ty);
                let inner = self.to_val(t, &x, depth + 1);
                format!("{{ let mut w = crate::proto::{w}::new(); for {x} in ({e}).iter() {{ w.items_mut().push({inner}); }} w }}")
            }
            Ty::Map(kt, vt) => {
                let w = self.proto_type(ty);
                let kv = self.map_key(kt, &k, depth + 1);
                let vv = self.to_val(vt, &x, depth + 1);
                format!("{{ let mut w = crate::proto::{w}::new(); for ({k}, {x}) in ({e}).iter() {{ w.entries_mut().insert({kv}, {vv}); }} w }}")
            }
        }
    }

    /// Map keys are passed as views: `&str` for string keys.
    fn map_key(&mut self, ty: &Ty, e: &str, depth: usize) -> String {
        let value = self.to_val(ty, e, depth);
        if self.proto_type(ty) == "string" {
            format!("({value}).as_str()")
        } else {
            value
        }
    }

    /// `v`: expression of the proto view of `ty` → expression of `T` (uses `?`).
    fn from_val(&mut self, ty: &Ty, v: &str, ctx: &str, depth: usize) -> String {
        let x = format!("x{depth}");
        let k = format!("k{depth}");
        let res = "::std::result::Result<_, crate::proto::ProtoError>";
        match ty {
            Ty::Prim(p) => match p {
                Prim::String => format!("crate::proto::convert::string_from({v})?"),
                Prim::PathBuf => format!("::std::path::PathBuf::from(crate::proto::convert::string_from({v})?)"),
                Prim::IpAddr => format!("crate::proto::convert::ip_from({v}, \"{ctx}\")?"),
                Prim::Bool | Prim::U32 | Prim::U64 | Prim::I32 | Prim::I64 | Prim::F32 | Prim::F64 => format!("({v})"),
                Prim::U8 | Prim::U16 | Prim::Usize => format!("crate::proto::convert::narrow({v}, \"{ctx}\")?"),
                Prim::Duration => format!("crate::proto::convert::duration_from_proto({v}, \"{ctx}\")?"),
                Prim::DateTime => format!("crate::proto::convert::timestamp_from_proto({v}, \"{ctx}\")?"),
            },
            Ty::Named(..) => format!("crate::proto::convert::FromProtoValue::from_proto_value({v})?"),
            Ty::Box(t) => format!("::std::boxed::Box::new({})", self.from_val(t, v, ctx, depth)),
            Ty::Result(..) => panic!("Result outside a struct field"),
            Ty::Option(t) => {
                self.proto_type(ty);
                let inner = self.from_val(t, &x, ctx, depth + 1);
                format!("match ({v}).value_opt() {{ ::std::option::Option::Some({x}) => ::std::option::Option::Some({inner}), ::std::option::Option::None => ::std::option::Option::None }}")
            }
            Ty::Vec(t) | Ty::Set(t) => {
                self.proto_type(ty);
                let inner = self.from_val(t, &x, ctx, depth + 1);
                format!("({v}).items().iter().map(|{x}| -> {res} {{ ::std::result::Result::Ok({inner}) }}).collect::<{res}>()?")
            }
            Ty::Map(kt, vt) => {
                self.proto_type(ty);
                let kv = self.from_val(kt, &k, ctx, depth + 1);
                let vv = self.from_val(vt, &x, ctx, depth + 1);
                format!("({v}).entries().iter().map(|({k}, {x})| -> {res} {{ ::std::result::Result::Ok(({kv}, {vv})) }}).collect::<{res}>()?")
            }
        }
    }

    /// Statements writing field `f` (`e`: `&T`) into proto message `m`.
    fn field_to(&mut self, f: &Field, e: &str, m: &str) -> String {
        let pf = &f.proto;
        let code = match &f.ty {
            Ty::Option(t) => {
                let inner = self.to_val(t, "x0", 1);
                format!("if let ::std::option::Option::Some(x0) = {e} {{ {m}.set_{pf}({inner}); }}")
            }
            Ty::Vec(t) | Ty::Set(t) => {
                let inner = self.to_val(t, "x0", 1);
                format!("for x0 in ({e}).iter() {{ {m}.{pf}_mut().push({inner}); }}")
            }
            Ty::Map(kt, vt) => {
                let kv = self.map_key(kt, "k0", 1);
                let vv = self.to_val(vt, "x0", 1);
                format!("for (k0, x0) in ({e}).iter() {{ {m}.{pf}_mut().insert({kv}, {vv}); }}")
            }
            Ty::Result(t, er) => {
                let ok = self.to_val(t, "x0", 1);
                let err = self.to_val(er, "x0", 1);
                format!("match {e} {{ ::std::result::Result::Ok(x0) => {m}.set_{pf}_ok({ok}), ::std::result::Result::Err(x0) => {m}.set_{pf}_err({err}) }}")
            }
            t => {
                let v = self.to_val(t, e, 0);
                format!("{m}.set_{pf}({v});")
            }
        };
        with_cfgs(&f.cfgs, &code)
    }

    /// Expression reading field `f` from proto view `p` (uses `?`).
    fn field_from(&mut self, f: &Field, p: &str, ctx: &str) -> String {
        let pf = &f.proto;
        let ctx = format!("{ctx}.{pf}");
        let res = "::std::result::Result<_, crate::proto::ProtoError>";
        match &f.ty {
            Ty::Option(t) => {
                let inner = self.from_val(t, "x0", &ctx, 1);
                format!("match {p}.{pf}_opt() {{ ::std::option::Option::Some(x0) => ::std::option::Option::Some({inner}), ::std::option::Option::None => ::std::option::Option::None }}")
            }
            Ty::Vec(t) | Ty::Set(t) => {
                let inner = self.from_val(t, "x0", &ctx, 1);
                format!("{p}.{pf}().iter().map(|x0| -> {res} {{ ::std::result::Result::Ok({inner}) }}).collect::<{res}>()?")
            }
            Ty::Map(kt, vt) => {
                let kv = self.from_val(kt, "k0", &ctx, 1);
                let vv = self.from_val(vt, "x0", &ctx, 1);
                format!("{p}.{pf}().iter().map(|(k0, x0)| -> {res} {{ ::std::result::Result::Ok(({kv}, {vv})) }}).collect::<{res}>()?")
            }
            Ty::Result(t, er) => {
                let ok = self.from_val(t, "x0", &ctx, 1);
                let err = self.from_val(er, "x0", &ctx, 1);
                format!("if let ::std::option::Option::Some(x0) = {p}.{pf}_ok_opt() {{ ::std::result::Result::Ok({ok}) }} else if let ::std::option::Option::Some(x0) = {p}.{pf}_err_opt() {{ ::std::result::Result::Err({err}) }} else {{ return ::std::result::Result::Err(crate::proto::ProtoError::MissingField(\"{ctx}\")) }}")
            }
            t => {
                if self.is_message(t) {
                    let v = format!("crate::proto::convert::required({p}.{pf}_opt(), \"{ctx}\")?");
                    self.from_val(t, &v, &ctx, 0)
                } else {
                    self.from_val(t, &format!("{p}.{pf}()"), &ctx, 0)
                }
            }
        }
    }

    fn sample(&mut self, ty: &Ty) -> String {
        match ty {
            Ty::Prim(p) => match p {
                Prim::String => "::std::string::String::from(\"sample\")".into(),
                Prim::PathBuf => "::std::path::PathBuf::from(\"/tmp/sample\")".into(),
                Prim::IpAddr => "\"192.0.2.1\".parse::<::std::net::IpAddr>().unwrap()".into(),
                Prim::Bool => "true".into(),
                Prim::U8 | Prim::U16 | Prim::U32 | Prim::U64 | Prim::Usize | Prim::I32 | Prim::I64 => "7".into(),
                Prim::F32 | Prim::F64 => "1.5".into(),
                Prim::Duration => "::std::time::Duration::from_millis(1500)".into(),
                Prim::DateTime => "::chrono::DateTime::from_timestamp(1_700_000_000, 5).unwrap()".into(),
            },
            Ty::Named(..) => "crate::proto::convert::first_sample()".into(),
            Ty::Box(t) => format!("::std::boxed::Box::new({})", self.sample(t)),
            Ty::Option(t) => format!("::std::option::Option::Some({})", self.sample(t)),
            Ty::Vec(t) => format!("::std::vec![{}]", self.sample(t)),
            Ty::Set(t) => format!("[{}].into_iter().collect()", self.sample(t)),
            Ty::Map(k, v) => format!("[({}, {})].into_iter().collect()", self.sample(k), self.sample(v)),
            Ty::Result(t, _) => format!("::std::result::Result::Ok({})", self.sample(t)),
        }
    }

    fn minimal_sample(&mut self, ty: &Ty) -> String {
        match ty {
            Ty::Option(_) => "::std::option::Option::None".into(),
            Ty::Vec(_) => "::std::vec::Vec::new()".into(),
            Ty::Set(_) | Ty::Map(..) => "::std::iter::empty().collect()".into(),
            Ty::Result(_, e) => format!("::std::result::Result::Err({})", self.sample(e)),
            other => self.sample(other),
        }
    }

    fn check_cycles(&self) -> Result<(), String> {
        // samples use Some/vec![..] for containers: a type reaching itself through
        // any path would recurse forever
        fn all_deps(g: &Gen, ty: &Ty, out: &mut Vec<usize>) {
            match ty {
                Ty::Prim(_) => {}
                Ty::Option(t) | Ty::Vec(t) | Ty::Set(t) | Ty::Box(t) => all_deps(g, t, out),
                Ty::Map(k, v) | Ty::Result(k, v) => {
                    all_deps(g, k, out);
                    all_deps(g, v, out);
                }
                Ty::Named(d, a) => out.push(g.inst_index[&(*d, a.clone())]),
            }
        }
        let edges: Vec<Vec<usize>> = self
            .insts
            .iter()
            .map(|inst| {
                let mut out = Vec::new();
                match &inst.repr {
                    Repr::Message { fields, .. } => fields.iter().for_each(|f| all_deps(self, &f.ty, &mut out)),
                    Repr::Transparent(t) => all_deps(self, t, &mut out),
                    Repr::Enum(variants) => {
                        // a recursive enum is fine if one variant avoids recursion;
                        // samples of the first variant only are used by others
                        if let Some(v) = variants.first() {
                            match &v.kind {
                                VariantKind::Unit => {}
                                VariantKind::Tuple(f) | VariantKind::Struct(f) => {
                                    f.iter().for_each(|f| all_deps(self, &f.ty, &mut out))
                                }
                            }
                        }
                    }
                }
                out
            })
            .collect();
        fn visit(i: usize, edges: &[Vec<usize>], state: &mut [u8], g: &Gen) -> Result<(), String> {
            if state[i] == 2 {
                return Ok(());
            }
            if state[i] == 1 {
                return Err(format!("recursive type through `{}`: not supported", g.insts[i].proto_name));
            }
            state[i] = 1;
            for j in &edges[i] {
                visit(*j, edges, state, g)?;
            }
            state[i] = 2;
            Ok(())
        }
        let mut state = vec![0u8; self.insts.len()];
        for i in 0..self.insts.len() {
            visit(i, &edges, &mut state, self)?;
        }
        Ok(())
    }

    // ---------------- proto emission ----------------

    fn lock_entry(&mut self, message: &str, repr: &str) -> Result<LockEntry, String> {
        let entry = self.lock.messages.entry(message.to_string()).or_insert_with(|| LockEntry {
            repr: repr.to_string(),
            ..Default::default()
        });
        if entry.repr != repr {
            return Err(format!(
                "`{message}` changed representation ({} → {repr}): this breaks the wire format. \
                 Rename the type (new message) or, if no data in this format exists yet, delete its lock entry.",
                entry.repr
            ));
        }
        Ok(entry.clone())
    }

    fn save_entry(&mut self, message: &str, entry: LockEntry, used: BTreeSet<String>) {
        self.lock.messages.insert(message.to_string(), entry);
        self.used.insert(message.to_string(), used);
    }

    fn emit_fields(&mut self, message: &str, fields: &[Field], out: &mut String) -> Result<(), String> {
        let mut entry = self.lock_entry(message, "message")?;
        let mut used = BTreeSet::new();
        for f in fields {
            let pf = f.proto.clone();
            match &f.ty {
                Ty::Result(t, e) => {
                    let ok = format!("{pf}_ok");
                    let err = format!("{pf}_err");
                    let (n_ok, n_err) = (entry.number(&ok), entry.number(&err));
                    let (t_ok, t_err) = (self.proto_type(t), self.proto_type(e));
                    writeln!(out, "  oneof {pf} {{\n    {t_ok} {ok} = {n_ok};\n    {t_err} {err} = {n_err};\n  }}").unwrap();
                    used.insert(ok);
                    used.insert(err);
                }
                ty => {
                    let decl = self.field_decl(ty);
                    let n = entry.number(&pf);
                    writeln!(out, "  {decl} {pf} = {n};").unwrap();
                    used.insert(pf);
                }
            }
        }
        self.emit_reserved(&entry, &used, out);
        self.save_entry(message, entry, used);
        Ok(())
    }

    fn emit_reserved(&self, entry: &LockEntry, used: &BTreeSet<String>, out: &mut String) {
        let mut retired: Vec<(String, u32)> = entry.retired.iter().map(|(k, v)| (k.clone(), *v)).collect();
        retired.extend(entry.fields.iter().filter(|(k, _)| !used.contains(*k)).map(|(k, v)| (k.clone(), *v)));
        retired.sort_by_key(|(_, n)| *n);
        for (name, n) in retired {
            writeln!(out, "  reserved {n};\n  reserved \"{name}\";").unwrap();
        }
    }

    fn field_decl(&mut self, ty: &Ty) -> String {
        match ty {
            Ty::Option(t) => {
                let pt = self.proto_type(t);
                if self.is_message(t) { pt } else { format!("optional {pt}") }
            }
            Ty::Vec(t) | Ty::Set(t) => format!("repeated {}", self.proto_type(t)),
            Ty::Map(k, v) => {
                let kt = self.proto_type(k);
                if self.is_message(k) {
                    panic!("map key must be a scalar: {}", self.name_of(k));
                }
                format!("map<{kt}, {}>", self.proto_type(v))
            }
            t => self.proto_type(t),
        }
    }

    fn emit_proto(&mut self) -> Result<String, String> {
        let mut out = String::new();
        out.push_str(
            "// @generated by tools/protogen from regent-sdk's Rust types. Do not edit:\n\
             // run `cargo run --manifest-path tools/protogen/Cargo.toml` from the regent-sdk root.\n\
             //\n\
             // Wire-compatibility rules (enforced through protogen.lock.json): field numbers\n\
             // are never reused or renumbered; removed fields stay `reserved`.\n\n\
             syntax = \"proto3\";\n\npackage regent.v1;\n\n\
             // Carried by enum variants without data.\nmessage Unit {}\n\n\
             // chrono::DateTime<Utc>\nmessage Timestamp {\n  int64 seconds = 1;\n  uint32 nanos = 2;\n}\n\n\
             // std::time::Duration\nmessage RustDuration {\n  uint64 seconds = 1;\n  uint32 nanos = 2;\n}\n",
        );
        let order: Vec<usize> = {
            let mut v: Vec<usize> = (0..self.insts.len()).collect();
            v.sort_by_key(|i| self.insts[*i].proto_name.clone());
            v
        };
        for i in order {
            let name = self.insts[i].proto_name.clone();
            let def = self.insts[i].def;
            let rust = format!("crate::{}::{}", self.defs[def].module.join("::"), self.defs[def].name).replace("crate::::", "crate::");
            match std::mem::replace(&mut self.insts[i].repr, Repr::Transparent(Ty::Prim(Prim::Bool))) {
                Repr::Transparent(inner) => {
                    let entry = self.lock_entry(&name, "transparent")?;
                    self.save_entry(&name, entry, BTreeSet::new());
                    self.insts[i].repr = Repr::Transparent(inner);
                }
                Repr::Message { fields, tuple, unit } => {
                    writeln!(out, "\n// {rust}\nmessage {name} {{").unwrap();
                    self.emit_fields(&name, &fields, &mut out)?;
                    out.push_str("}\n");
                    self.insts[i].repr = Repr::Message { fields, tuple, unit };
                }
                Repr::Enum(variants) => {
                    let mut entry = self.lock_entry(&name, "oneof")?;
                    let mut used = BTreeSet::new();
                    let mut nested = String::new();
                    writeln!(out, "\n// {rust}\nmessage {name} {{\n  oneof variant_kind {{").unwrap();
                    for v in &variants {
                        let n = entry.number(&v.case);
                        used.insert(v.case.clone());
                        let ty = match &v.kind {
                            VariantKind::Unit => "Unit".to_string(),
                            VariantKind::Tuple(f) if f.len() == 1 => self.proto_type(&f[0].ty),
                            VariantKind::Tuple(f) | VariantKind::Struct(f) => {
                                let nested_name = format!("{name}_{}", v.name);
                                writeln!(nested, "\n// {rust}::{}\nmessage {nested_name} {{", v.name).unwrap();
                                self.emit_fields(&nested_name, f, &mut nested)?;
                                nested.push_str("}\n");
                                nested_name
                            }
                        };
                        writeln!(out, "    {ty} {} = {n};", v.case).unwrap();
                    }
                    out.push_str("  }\n");
                    self.emit_reserved(&entry, &used, &mut out);
                    out.push_str("}\n");
                    out.push_str(&nested);
                    self.save_entry(&name, entry, used);
                    self.insts[i].repr = Repr::Enum(variants);
                }
            }
        }
        // wrappers (fixed layout, no lock entries)
        let mut emitted = BTreeSet::new();
        loop {
            let pending: Vec<(String, Ty)> = self
                .wrappers
                .iter()
                .filter(|(n, _)| !emitted.contains(*n))
                .map(|(n, t)| (n.clone(), t.clone()))
                .collect();
            if pending.is_empty() {
                break;
            }
            for (name, ty) in pending {
                let body = match &ty {
                    Ty::Option(t) => format!("  {} value = 1;", self.field_decl(&Ty::Option(t.clone()))),
                    Ty::Vec(t) | Ty::Set(t) => format!("  repeated {} items = 1;", self.proto_type(t)),
                    Ty::Map(k, v) => format!("  {} entries = 1;", self.field_decl(&Ty::Map(k.clone(), v.clone()))),
                    _ => unreachable!(),
                };
                writeln!(out, "\n// wrapper for a nested container\nmessage {name} {{\n{body}\n}}").unwrap();
                emitted.insert(name);
            }
        }
        Ok(out)
    }

    fn retire_unused(&mut self) {
        for (message, entry) in self.lock.messages.iter_mut() {
            let Some(used) = self.used.get(message) else { continue };
            let gone: Vec<String> = entry.fields.keys().filter(|k| !used.contains(*k)).cloned().collect();
            for k in gone {
                let n = entry.fields.remove(&k).unwrap();
                entry.retired.insert(k, n);
            }
        }
    }

    // ---------------- Rust emission ----------------

    fn emit_rust(&mut self) -> Result<BTreeMap<String, (PathBuf, String)>, String> {
        let mut files: BTreeMap<String, (PathBuf, String)> = BTreeMap::new();
        for i in 0..self.insts.len() {
            let def = self.insts[i].def;
            let file_name = format!(
                "{}.rs",
                if self.defs[def].module.is_empty() { "lib".to_string() } else { self.defs[def].module.join("__") }
            );
            let source = self.defs[def].file.clone();
            let code = self.emit_inst(i)?;
            let entry = files.entry(file_name).or_insert_with(|| {
                (
                    source.clone(),
                    "// @generated by tools/protogen. Do not edit: run\n\
                     // `cargo run --manifest-path tools/protogen/Cargo.toml` from the regent-sdk root.\n\
                     #![allow(unused_imports, unused_variables, unused_mut, unused_parens, clippy::all)]\n\n\
                     use super::*;\n"
                        .to_string(),
                )
            });
            entry.1.push_str(&code);
        }
        Ok(files)
    }

    fn rust_type_name(&self, i: usize) -> String {
        let inst = &self.insts[i];
        let def = &self.defs[inst.def];
        if inst.args.is_empty() {
            return def.name.clone();
        }
        let args: Vec<String> = inst.args.iter().map(|a| self.rust_ty(a)).collect();
        format!("{}<{}>", def.name, args.join(", "))
    }

    fn rust_ty(&self, ty: &Ty) -> String {
        match ty {
            Ty::Prim(p) => match p {
                Prim::String => "::std::string::String".into(),
                Prim::Bool => "bool".into(),
                Prim::U8 => "u8".into(),
                Prim::U16 => "u16".into(),
                Prim::U32 => "u32".into(),
                Prim::U64 => "u64".into(),
                Prim::Usize => "usize".into(),
                Prim::I32 => "i32".into(),
                Prim::I64 => "i64".into(),
                Prim::F32 => "f32".into(),
                Prim::F64 => "f64".into(),
                Prim::PathBuf => "::std::path::PathBuf".into(),
                Prim::IpAddr => "::std::net::IpAddr".into(),
                Prim::Duration => "::std::time::Duration".into(),
                Prim::DateTime => "::chrono::DateTime<::chrono::Utc>".into(),
            },
            Ty::Named(d, a) => {
                let i = self.inst_index[&(*d, a.clone())];
                self.rust_type_name(i)
            }
            _ => panic!("generic argument must be a scalar or named type"),
        }
    }

    fn emit_inst(&mut self, i: usize) -> Result<String, String> {
        let rust_name = self.rust_type_name(i);
        let proto_name = self.insts[i].proto_name.clone();
        let type_name = self.defs[self.insts[i].def].name.clone();
        let fallback = FALLBACKS.iter().find(|(n, _)| *n == type_name).map(|(_, e)| e.to_string());
        let repr = std::mem::replace(&mut self.insts[i].repr, Repr::Transparent(Ty::Prim(Prim::Bool)));
        let mut out = String::new();
        let res = "::std::result::Result<Self, crate::proto::ProtoError>";
        let test_name = snake(&proto_name.replace('_', ""));
        let derives = &self.defs[self.insts[i].def].derives;
        // compare through serde when derived (the most complete view), else Debug
        let oracle = if derives.iter().any(|d| d == "Serialize") {
            Some("assert_roundtrip")
        } else if derives.iter().any(|d| d == "Debug") {
            Some("assert_roundtrip_debug")
        } else {
            None
        };
        let test = |rust_name: &str| -> String {
            match oracle {
                Some(f) => format!(
                    "#[cfg(test)]\n#[test]\nfn proto_roundtrip_{test_name}() {{\n    for sample in <{rust_name} as crate::proto::convert::ProtoSample>::proto_samples() {{\n        crate::proto::convert::{f}(&sample);\n    }}\n}}\n"
                ),
                None => String::new(),
            }
        };
        match &repr {
            Repr::Transparent(inner) => {
                let out_t = self.out_type(inner);
                let in_t = self.view_type(inner);
                let to = self.to_val(inner, "&self.0", 0);
                let from = self.from_val(inner, "v", &proto_name, 0);
                let sample = self.sample(inner);
                write!(
                    out,
                    "\nimpl crate::proto::convert::IntoProtoValue for {rust_name} {{\n    type Out = {out_t};\n    fn into_proto_value(&self) -> Self::Out {{ {to} }}\n}}\n\n\
                     impl<'a> crate::proto::convert::FromProtoValue<'a> for {rust_name} {{\n    type In = {in_t};\n    fn from_proto_value(v: Self::In) -> {res} {{ ::std::result::Result::Ok(Self({from})) }}\n}}\n\n\
                     #[cfg(test)]\nimpl crate::proto::convert::ProtoSample for {rust_name} {{\n    fn proto_samples() -> ::std::vec::Vec<Self> {{ ::std::vec![Self({sample})] }}\n}}\n"
                )
                .unwrap();
            }
            Repr::Message { fields, tuple, unit } => {
                let mut to = String::new();
                let mut from = String::new();
                let mut full = Vec::new();
                let mut minimal = Vec::new();
                for f in fields {
                    to.push_str("        ");
                    to.push_str(&self.field_to(f, &format!("&self.{}", f.rust), "m"));
                    to.push('\n');
                    let value = self.field_from(f, "p", &proto_name);
                    let s_full = self.sample(&f.ty);
                    let s_min = self.minimal_sample(&f.ty);
                    if *tuple {
                        from.push_str(&format!("{value}, "));
                        full.push(s_full);
                        minimal.push(s_min);
                    } else {
                        from.push_str(&format!("{}: {value}, ", f.rust));
                        full.push(format!("{}: {s_full}", f.rust));
                        minimal.push(format!("{}: {s_min}", f.rust));
                    }
                }
                let build = |items: String| -> String {
                    if *unit { "Self".to_string() } else if *tuple { format!("Self({items})") } else { format!("Self {{ {items} }}") }
                };
                let from_expr = build(from);
                let sample_full = build(full.join(", "));
                let sample_min = build(minimal.join(", "));
                write!(
                    out,
                    "\nimpl crate::proto::convert::IntoProtoValue for {rust_name} {{\n    type Out = crate::proto::{proto_name};\n    fn into_proto_value(&self) -> Self::Out {{\n        let mut m = crate::proto::{proto_name}::new();\n{to}        m\n    }}\n}}\n\n\
                     impl<'a> crate::proto::convert::FromProtoValue<'a> for {rust_name} {{\n    type In = ::protobuf::View<'a, crate::proto::{proto_name}>;\n    fn from_proto_value(p: Self::In) -> {res} {{\n        ::std::result::Result::Ok({from_expr})\n    }}\n}}\n\n\
                     #[cfg(test)]\nimpl crate::proto::convert::ProtoSample for {rust_name} {{\n    fn proto_samples() -> ::std::vec::Vec<Self> {{ ::std::vec![{sample_full}, {sample_min}] }}\n}}\n\n\
                     {test}",
                    test = test(&rust_name)
                )
                .unwrap();
            }
            Repr::Enum(variants) => {
                let mut to_arms = String::new();
                let mut from_arms = String::new();
                let mut samples = String::new();
                for v in variants {
                    let case = &v.case;
                    let vname = &v.name;
                    let cfg = v.cfgs.join(" ");
                    match &v.kind {
                        VariantKind::Unit => {
                            writeln!(to_arms, "            {cfg} Self::{vname} => m.set_{case}(crate::proto::Unit::new()),").unwrap();
                            writeln!(from_arms, "        {cfg} if p.has_{case}() {{ return ::std::result::Result::Ok(Self::{vname}); }}").unwrap();
                            writeln!(samples, "        {cfg} out.push(Self::{vname});").unwrap();
                        }
                        VariantKind::Tuple(fields) if fields.len() == 1 => {
                            let t = &fields[0].ty;
                            let to = self.to_val(t, "a0", 0);
                            let ctx = format!("{proto_name}.{case}");
                            let from = self.from_val(t, "x", &ctx, 0);
                            let s = self.sample(t);
                            writeln!(to_arms, "            {cfg} Self::{vname}(a0) => m.set_{case}({to}),").unwrap();
                            writeln!(from_arms, "        {cfg} if let ::std::option::Option::Some(x) = p.{case}_opt() {{ return ::std::result::Result::Ok(Self::{vname}({from})); }}").unwrap();
                            writeln!(samples, "        {cfg} out.push(Self::{vname}({s}));").unwrap();
                        }
                        VariantKind::Tuple(fields) | VariantKind::Struct(fields) => {
                            let nested = format!("{proto_name}_{vname}");
                            let is_tuple = matches!(v.kind, VariantKind::Tuple(_));
                            let bindings: Vec<String> = fields
                                .iter()
                                .enumerate()
                                .map(|(i, f)| if is_tuple { format!("a{i}") } else { f.rust.clone() })
                                .collect();
                            let mut set = String::new();
                            let mut get = Vec::new();
                            let mut samp = Vec::new();
                            for (f, b) in fields.iter().zip(&bindings) {
                                set.push_str(&self.field_to(f, b, "c"));
                                set.push(' ');
                                let value = self.field_from(f, "c", &nested);
                                let s = self.sample(&f.ty);
                                if is_tuple {
                                    get.push(value);
                                    samp.push(s);
                                } else {
                                    get.push(format!("{}: {value}", f.rust));
                                    samp.push(format!("{}: {s}", f.rust));
                                }
                            }
                            let (pat, ctor, sample) = if is_tuple {
                                (format!("Self::{vname}({})", bindings.join(", ")), format!("Self::{vname}({})", get.join(", ")), format!("Self::{vname}({})", samp.join(", ")))
                            } else {
                                (format!("Self::{vname} {{ {} }}", bindings.join(", ")), format!("Self::{vname} {{ {} }}", get.join(", ")), format!("Self::{vname} {{ {} }}", samp.join(", ")))
                            };
                            writeln!(to_arms, "            {cfg} {pat} => {{ let mut c = crate::proto::{nested}::new(); {set}m.set_{case}(c); }}").unwrap();
                            writeln!(from_arms, "        {cfg} if let ::std::option::Option::Some(c) = p.{case}_opt() {{ return ::std::result::Result::Ok({ctor}); }}").unwrap();
                            writeln!(samples, "        {cfg} out.push({sample});").unwrap();
                        }
                    }
                }
                let decode_fn = format!(
                    "impl {rust_name} {{\n    fn protogen_decode(p: ::protobuf::View<'_, crate::proto::{proto_name}>) -> {res} {{\n{from_arms}        ::std::result::Result::Err(crate::proto::ProtoError::UnknownVariant(\"{proto_name}\"))\n    }}\n}}\n"
                );
                let from_body = match &fallback {
                    Some(expr) => format!(
                        "match Self::protogen_decode(p) {{\n            ::std::result::Result::Err(crate::proto::ProtoError::UnknownVariant(unknown)) => ::std::result::Result::Ok({expr}),\n            other => other,\n        }}"
                    ),
                    None => "Self::protogen_decode(p)".to_string(),
                };
                write!(
                    out,
                    "\nimpl crate::proto::convert::IntoProtoValue for {rust_name} {{\n    type Out = crate::proto::{proto_name};\n    fn into_proto_value(&self) -> Self::Out {{\n        let mut m = crate::proto::{proto_name}::new();\n        match self {{\n{to_arms}        }}\n        m\n    }}\n}}\n\n\
                     {decode_fn}\n\
                     impl<'a> crate::proto::convert::FromProtoValue<'a> for {rust_name} {{\n    type In = ::protobuf::View<'a, crate::proto::{proto_name}>;\n    fn from_proto_value(p: Self::In) -> {res} {{\n        {from_body}\n    }}\n}}\n\n\
                     #[cfg(test)]\nimpl crate::proto::convert::ProtoSample for {rust_name} {{\n    fn proto_samples() -> ::std::vec::Vec<Self> {{\n        let mut out = ::std::vec::Vec::new();\n{samples}        out\n    }}\n}}\n\n\
                     {test}",
                    test = test(&rust_name)
                )
                .unwrap();
            }
        }
        self.insts[i].repr = repr;
        Ok(out)
    }
}

fn with_cfgs(cfgs: &[String], code: &str) -> String {
    if cfgs.is_empty() {
        code.to_string()
    } else {
        format!("{} {{ {code} }}", cfgs.join(" "))
    }
}

/// Make sure `source_file` declares the generated child module.
fn ensure_mod_line(root: &Path, source_file: &Path, file_name: &str) -> Result<(), String> {
    let path = root.join(source_file);
    let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let depth = source_file.parent().unwrap().strip_prefix("src").unwrap().iter().count();
    let relative = format!("{}proto/conv/{file_name}", "../".repeat(depth));
    let line = format!("#[cfg(feature = \"proto\")]\n#[path = \"{relative}\"]\nmod proto_conv;\n");
    if raw.contains(&line) {
        return Ok(());
    }
    if raw.contains("mod proto_conv;") {
        return Err(format!("{}: has a different `mod proto_conv;` declaration", path.display()));
    }
    let mut updated = raw;
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push('\n');
    updated.push_str(&line);
    std::fs::write(&path, updated).map_err(|e| e.to_string())?;
    eprintln!("added `mod proto_conv;` to {}", path.display());
    Ok(())
}
