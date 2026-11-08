//! JSON Schema of expected states and attributes (feature `schema`), as the
//! YAML/JSON forms read by serde: e.g. to build attribute forms in a UI and
//! keep them in step with the SDK.

use schemars::Schema;

use crate::state::ExpectedState;
use crate::state::attribute::Attribute;

/// Schema of one [`Attribute`] (`Name`, `Privilege`, `Detail`, `Timeout`).
pub fn attribute() -> Schema {
    schemars::schema_for!(Attribute)
}

/// Schema of an [`ExpectedState`] (its `Attributes`).
pub fn expected_state() -> Schema {
    schemars::schema_for!(ExpectedState)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    // Minimal instances generated from the schema: every variant of every
    // oneOf/anyOf, required properties only, placeholder scalars.

    struct Gen<'a> {
        defs: &'a serde_json::Map<String, Value>,
    }

    impl Gen<'_> {
        fn resolve<'b>(&'b self, schema: &'b Value) -> &'b Value {
            match schema.get("$ref").and_then(Value::as_str) {
                Some(r) => self
                    .defs
                    .get(r.trim_start_matches("#/$defs/"))
                    .unwrap_or(schema),
                None => schema,
            }
        }

        /// Every alternative instance (one per variant at the top, first variant below).
        fn variants(&self, schema: &Value) -> Vec<Value> {
            let schema = self.resolve(schema);
            for key in ["oneOf", "anyOf"] {
                if let Some(alts) = schema.get(key).and_then(Value::as_array) {
                    return alts.iter().map(|a| self.one(a, 0)).collect();
                }
            }
            if let Some(e) = schema.get("enum").and_then(Value::as_array) {
                return e.clone();
            }
            vec![self.one(schema, 0)]
        }

        fn one(&self, schema: &Value, depth: usize) -> Value {
            let schema = self.resolve(schema);
            if depth > 12 {
                return Value::Null;
            }
            if let Some(c) = schema.get("const") {
                return c.clone();
            }
            if let Some(e) = schema.get("enum").and_then(Value::as_array) {
                return e[0].clone();
            }
            // an object with its own properties and a oneOf (a flattened enum):
            // both apply, merge them
            if schema.get("properties").is_some() && schema.get("oneOf").is_some() {
                let mut base = schema.clone();
                let alts = base.as_object_mut().unwrap().remove("oneOf").unwrap();
                let mut out = self.one(&base, depth + 1);
                if let (Some(o), Value::Object(extra)) =
                    (out.as_object_mut(), self.one(&alts[0], depth + 1))
                {
                    o.extend(extra);
                }
                return out;
            }
            for key in ["oneOf", "anyOf"] {
                if let Some(alts) = schema.get(key).and_then(Value::as_array) {
                    // prefer a non-null alternative
                    let alt = alts
                        .iter()
                        .find(|a| a.get("type") != Some(&json!("null")))
                        .unwrap_or(&alts[0]);
                    return self.one(alt, depth + 1);
                }
            }
            if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
                return self.one(&all[0], depth + 1);
            }
            let ty = match schema.get("type") {
                Some(Value::Array(types)) => types
                    .iter()
                    .find(|t| *t != "null")
                    .cloned()
                    .unwrap_or(Value::Null),
                Some(t) => t.clone(),
                None if schema.get("properties").is_some() => json!("object"),
                None => return json!("x"),
            };
            match ty.as_str().unwrap_or("null") {
                "object" => {
                    let mut out = serde_json::Map::new();
                    let required: Vec<&str> = schema
                        .get("required")
                        .and_then(Value::as_array)
                        .map(|r| r.iter().filter_map(Value::as_str).collect())
                        .unwrap_or_default();
                    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                        for (k, v) in props {
                            if required.contains(&k.as_str()) {
                                out.insert(k.clone(), self.one(v, depth + 1));
                            }
                        }
                    }
                    Value::Object(out)
                }
                "array" => {
                    let min = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
                    let item = schema
                        .get("items")
                        .map(|i| self.one(i, depth + 1))
                        .unwrap_or(json!("x"));
                    Value::Array((0..min.max(1)).map(|_| item.clone()).collect())
                }
                "string" => match schema.get("pattern").and_then(Value::as_str) {
                    Some(p) if p.contains("[0-9]+") && !p.contains("a-z") => json!("1.2.3"),
                    Some(_) => json!("x1"),
                    None => json!("/x"),
                },
                "integer" => json!(
                    schema
                        .get("minimum")
                        .and_then(Value::as_i64)
                        .unwrap_or(1)
                        .max(1)
                ),
                "number" => json!(1.0),
                "boolean" => json!(false),
                _ => Value::Null,
            }
        }
    }

    /// The other direction of "the schema describes what serde reads": an
    /// instance generated from the schema, for every variant of every
    /// attribute type, deserializes into an [`Attribute`](crate::state::attribute::Attribute).
    #[test]
    fn instances_of_the_schema_deserialize() {
        let schema = serde_json::to_value(super::attribute()).unwrap();
        let defs = schema["$defs"].as_object().unwrap();
        let generator = Gen { defs };
        let mut kinds = 0;
        for detail in generator.variants(&schema["properties"]["Detail"]) {
            let kind = detail
                .as_object()
                .and_then(|o| o.keys().next())
                .cloned()
                .unwrap();
            kinds += 1;
            let def = defs
                .get(&format!("{kind}ExpectedState"))
                .cloned()
                .unwrap_or(Value::Null);
            let mut details: Vec<Value> = generator
                .variants(&def)
                .into_iter()
                .map(|inner| json!({ kind.clone(): inner }))
                .collect();
            if def.is_null() {
                details = vec![detail.clone()];
            }
            for detail in details {
                let attribute = json!({"Name": "n", "Privilege": "None", "Detail": detail});
                if let Err(e) =
                    serde_json::from_value::<crate::state::attribute::Attribute>(attribute.clone())
                {
                    panic!("{kind}: {e}\n{}", attribute["Detail"]);
                }
            }
        }
        assert_eq!(kinds, 32);
    }

    #[test]
    fn every_attribute_type_is_described() {
        let schema = serde_json::to_value(super::attribute()).unwrap();
        let text = schema.to_string();
        for kind in ["LineInFile", "Apt", "Command", "Service", "Docker", "Alloy"] {
            assert!(text.contains(&format!("\"{kind}\"")), "{kind} missing");
        }
    }
}
