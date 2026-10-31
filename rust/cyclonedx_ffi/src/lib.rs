use cyclonedx_bom::models::bom::Bom;
use cyclonedx_bom::prelude::SpecVersion;
use serde::Deserialize;
use serde_json::{json, Value};
use std::ffi::{CStr, CString};
use std::io::Cursor;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

#[derive(Debug, Deserialize)]
struct EmitDocument {
    #[serde(default)]
    components: Vec<EmitComponent>,
    #[serde(default)]
    dependencies: Vec<EmitDependency>,
    #[serde(default)]
    vulnerabilities: Vec<EmitVulnerability>,
}

#[derive(Debug, Deserialize)]
struct EmitComponent {
    bom_ref: String,
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    system: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default)]
    local_target: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct EmitDependency {
    r#ref: String,
    #[serde(default)]
    depends_on: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EmitVulnerability {
    id: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    analysis_detail: Option<String>,
    #[serde(default)]
    affects_ref: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct ParsedComponent {
    bom_ref: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct ParsedInventory {
    components: Vec<ParsedComponent>,
}

fn component_json(item: &EmitComponent) -> Value {
    let mut properties = Vec::new();
    if let Some(system) = &item.system {
        if !system.is_empty() {
            properties.push(json!({"name": "reqpack:system", "value": system}));
        }
    }
    if let Some(source_path) = &item.source_path {
        if !source_path.is_empty() {
            properties.push(json!({"name": "reqpack:sourcePath", "value": source_path}));
        }
    }
    if item.local_target.unwrap_or(false) {
        properties.push(json!({"name": "reqpack:localTarget", "value": "true"}));
    }

    let mut component = json!({
        "type": "library",
        "bom-ref": item.bom_ref,
        "name": item.name,
    });
    if let Some(version) = &item.version {
        if !version.is_empty() {
            component["version"] = Value::String(version.clone());
        }
    }
    if let Some(purl) = &item.purl {
        if !purl.is_empty() {
            component["purl"] = Value::String(purl.clone());
        }
    }
    if !properties.is_empty() {
        component["properties"] = Value::Array(properties);
    }
    component
}

fn vulnerability_json(item: &EmitVulnerability) -> Value {
    let source_name = item
        .source
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "reqpack".to_string());
    let severity = item
        .severity
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unassigned".to_string());
    let score = item.score.unwrap_or(0.0);
    let detail = item
        .analysis_detail
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| item.description.clone().unwrap_or_default());

    let mut vulnerability = json!({
        "id": item.id,
        "source": {"name": source_name.clone()},
        "ratings": [{
            "source": {"name": source_name},
            "severity": severity,
            "score": score
        }],
        "analysis": {
            "state": "in_triage",
            "detail": detail
        }
    });
    if let Some(description) = &item.description {
        if !description.is_empty() {
            vulnerability["description"] = Value::String(description.clone());
        }
    }
    if let Some(affects_ref) = &item.affects_ref {
        if !affects_ref.is_empty() {
            vulnerability["affects"] = json!([{"ref": affects_ref}]);
        }
    }
    vulnerability
}

fn document_to_value(document: &EmitDocument) -> Value {
    let components: Vec<Value> = document.components.iter().map(component_json).collect();
    let mut root = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    });

    if !document.dependencies.is_empty() {
        let dependencies: Vec<Value> = document
            .dependencies
            .iter()
            .map(|edge| {
                json!({
                    "ref": edge.r#ref,
                    "dependsOn": edge.depends_on,
                })
            })
            .collect();
        root["dependencies"] = Value::Array(dependencies);
    }

    if !document.vulnerabilities.is_empty() {
        let vulnerabilities: Vec<Value> = document.vulnerabilities.iter().map(vulnerability_json).collect();
        root["vulnerabilities"] = Value::Array(vulnerabilities);
    }

    root
}

fn emit_json(document: &EmitDocument) -> Result<String, String> {
    let value = document_to_value(document);
    let bom = Bom::parse_json_value(value).map_err(|error| format!("cyclonedx validation failed: {error}"))?;
    let mut buffer = Vec::new();
    bom.output_as_json(&mut buffer, SpecVersion::V1_5)
        .map_err(|error| format!("cyclonedx json output failed: {error}"))?;
    String::from_utf8(buffer).map_err(|error| format!("invalid utf-8 output: {error}"))
}

fn parse_inventory_json(cyclonedx_json: &str) -> Result<String, String> {
    let bom = Bom::parse_from_json(Cursor::new(cyclonedx_json.as_bytes()))
        .map_err(|error| format!("cyclonedx parse failed: {error}"))?;
    let components = bom.components.map(|values| values.0).unwrap_or_default();

    let mut parsed = Vec::new();
    for component in components {
        let bom_ref = component.bom_ref.map(|value| value.to_string()).unwrap_or_default();
        let mut system = None;
        if let Some(properties) = component.properties {
            for property in properties.0 {
                if property.name.to_string() == "reqpack:system" {
                    system = Some(property.value.to_string());
                }
            }
        }
        let purl = component.purl.map(|value| value.to_string());
        parsed.push(ParsedComponent {
            bom_ref,
            name: component.name.to_string(),
            version: component.version.map(|value| value.to_string()),
            purl,
            system,
        });
    }

    serde_json::to_string(&ParsedInventory { components: parsed })
        .map_err(|error| format!("inventory json encode failed: {error}"))
}

fn c_string_or_error(error: &str) -> *mut c_char {
    CString::new(error.to_string()).ok().map(CString::into_raw).unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn rqp_cyclonedx_free(buffer: *mut c_char) {
    if buffer.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(buffer));
    }
}

#[no_mangle]
pub extern "C" fn rqp_cyclonedx_emit_json(input_json: *const c_char, out_json: *mut *mut c_char) -> i32 {
    if input_json.is_null() || out_json.is_null() {
        return -1;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        unsafe {
            *out_json = ptr::null_mut();
            let input = CStr::from_ptr(input_json).to_string_lossy();
            let document: EmitDocument =
                serde_json::from_str(&input).map_err(|error| format!("invalid emit document: {error}"))?;
            let payload = emit_json(&document)?;
            CString::new(payload)
                .map_err(|_| "output contained interior nul".to_string())
                .map(CString::into_raw)
        }
    }));

    match result {
        Ok(Ok(value)) => {
            unsafe {
                *out_json = value;
            }
            0
        }
        Ok(Err(error)) => {
            unsafe {
                *out_json = c_string_or_error(&error);
            }
            1
        }
        Err(_) => {
            unsafe {
                *out_json = c_string_or_error("rust panic in cyclonedx emit");
            }
            2
        }
    }
}

#[no_mangle]
pub extern "C" fn rqp_cyclonedx_parse_inventory_json(
    cyclonedx_json: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    if cyclonedx_json.is_null() || out_json.is_null() {
        return -1;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        unsafe {
            *out_json = ptr::null_mut();
            let input = CStr::from_ptr(cyclonedx_json).to_string_lossy();
            let payload = parse_inventory_json(&input)?;
            CString::new(payload)
                .map_err(|_| "output contained interior nul".to_string())
                .map(CString::into_raw)
        }
    }));

    match result {
        Ok(Ok(value)) => {
            unsafe {
                *out_json = value;
            }
            0
        }
        Ok(Err(error)) => {
            unsafe {
                *out_json = c_string_or_error(&error);
            }
            1
        }
        Err(_) => {
            unsafe {
                *out_json = c_string_or_error("rust panic in cyclonedx parse");
            }
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_inventory_bom() {
        let document = EmitDocument {
            components: vec![EmitComponent {
                bom_ref: "npm:demo@1.0.0".to_string(),
                name: "demo".to_string(),
                version: Some("1.0.0".to_string()),
                purl: Some("pkg:npm/demo@1.0.0".to_string()),
                system: Some("npm".to_string()),
                source_path: None,
                local_target: None,
            }],
            dependencies: vec![],
            vulnerabilities: vec![],
        };
        let json = emit_json(&document).expect("emit");
        assert!(json.contains("CycloneDX"));
        assert!(json.contains("demo"));
    }
}
