// Copyright (c) Cc-Policy Authors.
// Licensed under the Apache 2.0 license.

use anyhow::{anyhow, bail, Result};
use checked_command::{CheckedCommand, Error};
use oci_spec::runtime::Mount;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

const KUBECTL: &str = "kubectl";

const CC_POLICY_KEY: &str = "io.katacontainers.cc_policy";

// Supported keys used by valueFrom and EnvFrom
const CONFIG_MAP_KEY_REF: &str = "configMapKeyRef";
const FIELD_REF: &str = "fieldRef";
const RESOURCE_FIELD_REF: &str = "resourceFieldRef";
const SECRET_KEY_REF: &str = "secretKeyRef";

// Readonly volume type
// See: https://github.com/kubernetes/kubernetes/issues/60814
const VOLUME_TYPE_SECRET: &str = "secret";
const VOLUME_TYPE_CONFIG_MAP: &str = "configMap";
const VOLUME_TYPE_DOWNWARD_API: &str = "downwardAPI";
const VOLUME_TYPE_PROJECTED: &str = "projected";

const VOLUME_TYPE_EMPTY_DIR: &str = "emptyDir";
const VOLUME_TYPE_HOST_PATH: &str = "hostPath";

const SPEC_CONTAINERS: &str = "containers";
const SPEC_INIT_CONTAINERS: &str = "initContainers";

#[derive(PartialEq, Eq)]
pub enum VolumeType {
    Unknown,
    EmptyDir,
    Secret,
    ConfigMap,
    DownwardAPI,
    Projected,
    HostPath,
}

impl Default for VolumeType {
    fn default() -> Self {
        VolumeType::Unknown
    }
}
#[derive(Default)]
pub struct Volume {
    pub r#_type: VolumeType,
    pub readonly: bool,
    pub host_path: String,
    pub local: bool,
}

pub struct PodYaml<'input> {
    pub kind: &'input str,
    pub containers: Option<&'input Vec<serde_yaml::Value>>,
    pub init_containers: Option<&'input Vec<serde_yaml::Value>>,
    volumes: HashMap<String, Volume>,
}

#[derive(Default)]
pub struct SecurityContext {
    pub allow_elevated: bool,
    pub privileged: bool,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Debugging {
    pub tty: bool,
}

impl<'input> PodYaml<'input> {
    pub fn from(yaml: &'input serde_yaml::Value) -> Result<PodYaml> {
        let kind = if let Some(kind) = yaml.get("kind") {
            kind.as_str()
                .ok_or_else(|| anyhow!("failed to parse kind into str"))?
        } else {
            ""
        };

        let spec = match kind {
            "Pod" => &yaml["spec"],
            "Job" | "Deployment" | "ReplicationController" => &yaml["spec"]["template"]["spec"],
            _ => {
                bail!("unsupported kind: {}", kind);
            }
        };

        let volumes = Self::get_volmues(spec)?;

        let mut containers = None;
        if let Some(v) = spec.get(SPEC_CONTAINERS) {
            if let Some(seq) = v.as_sequence() {
                containers = Some(seq);
            }
        }

        let mut init_containers = None;
        if let Some(v) = spec.get(SPEC_INIT_CONTAINERS) {
            if let Some(seq) = v.as_sequence() {
                init_containers = Some(seq);
            }
        }

        Ok(PodYaml {
            kind,
            containers,
            init_containers,
            volumes,
        })
    }

    pub fn get_name(container: &serde_yaml::Value) -> Result<String> {
        let name = container["name"]
            .as_str()
            .ok_or_else(|| anyhow!("failed to parse name into string"))?;

        Ok(name.to_owned())
    }

    pub fn get_security_context(container: &serde_yaml::Value) -> Result<SecurityContext> {
        let mut context = SecurityContext::default();

        if let Some(security_context) = container.get("securityContext") {
            if let Some(privileged) = security_context.get("privileged") {
                let privileged = privileged
                    .as_bool()
                    .ok_or_else(|| anyhow!("failed to parse privileged into bool"))?;

                context.privileged = privileged;
            }

            if let Some(allow_elevated) = security_context.get("allowPrivilegeEscalation") {
                let allow_elevated = allow_elevated
                    .as_bool()
                    .ok_or_else(|| anyhow!("failed to parse allowPrivilegeEscalation into bool"))?;

                context.allow_elevated = allow_elevated;
            }
        }

        Ok(context)
    }

    fn get_value_from_config_map(map: &serde_yaml::Value) -> Result<String> {
        let map = map
            .as_mapping()
            .ok_or_else(|| anyhow!("failed in convert configMapKeyRef into map"))?;

        let name = map["name"]
            .as_str()
            .ok_or_else(|| anyhow!("failed to parse name into str"))?;

        let key = map["key"]
            .as_str()
            .ok_or_else(|| anyhow!("failed to parse key into str"))?;

        let output = match CheckedCommand::new(KUBECTL)
            .arg("get")
            .arg("configmap")
            .arg(name)
            .arg("-o")
            .arg("yaml")
            .output()
        {
            Ok(result) => String::from_utf8(result.stdout)?,
            Err(Error::Failure(ex, output)) => {
                println!("failed with exit code: {:?}", ex.code());
                if let Some(output) = output {
                    bail!(
                        "{}: kubectl failed: {}",
                        loc!(),
                        String::from_utf8_lossy(&*output.stderr)
                    );
                }
                bail!("{}", loc!());
            }
            Err(Error::Io(io_err)) => {
                bail!("{}: unexpected I/O error: {:?}", loc!(), io_err);
            }
        };

        let config_map: serde_yaml::Value = serde_yaml::from_str(&output)?;

        let data = config_map["data"]
            .as_mapping()
            .ok_or_else(|| anyhow!("failed to parse data into mapping"))?;

        if let Some(value) = data.get(key) {
            let value = value
                .as_str()
                .ok_or_else(|| anyhow!("failed to parse value into str"))?;

            return Ok(value.to_string());
        }

        bail!(
            "{} failed to find value using key {} from configMap {}",
            loc!(),
            key,
            name
        )
    }

    fn get_value_from(env: &serde_yaml::Value, name: &str) -> Result<(String, String)> {
        // default values
        let mut rule = [name, "="].concat();
        let mut strategy = String::from("string");

        if let Some(value_from) = env.get("valueFrom") {
            let value_from = value_from
                .as_mapping()
                .ok_or_else(|| anyhow!("failed to convert valueFrom into mapping"))?;

            if value_from.contains_key(CONFIG_MAP_KEY_REF) {
                let config_map = value_from.get(CONFIG_MAP_KEY_REF).unwrap();
                let value = Self::get_value_from_config_map(config_map)?;
                rule = ["^", name, "=", &value, "$"].concat();
                strategy = String::from("string");
            } else if value_from.contains_key(SECRET_KEY_REF)
                || value_from.contains_key(FIELD_REF)
                || value_from.contains_key(RESOURCE_FIELD_REF)
            {
                rule = ["^", name, "=."].concat();
                strategy = String::from("regex");
            } else {
                bail!("{} unsupported reference: {:?}", loc!(), value_from);
            }
        }

        Ok((rule, strategy))
    }

    pub fn get_volmues(spec: &serde_yaml::Value) -> Result<HashMap<String, Volume>> {
        let mut volumes = HashMap::new();

        if let Some(v) = spec.get("volumes") {
            if let Some(seq) = v.as_sequence() {
                for vol in seq {
                    let vol = vol
                        .as_mapping()
                        .ok_or_else(|| anyhow!("failed to convert volume into mapping"))?;

                    let name = vol["name"]
                        .as_str()
                        .ok_or_else(|| anyhow!("failed to parse name into str"))?;

                    let mut r#_type = VolumeType::default();
                    let mut readonly = false;
                    let mut host_path = String::new();
                    let mut local = false;

                    if vol.contains_key(VOLUME_TYPE_EMPTY_DIR) {
                        r#_type = VolumeType::EmptyDir;
                        // Only looking for the case of emptyDir: {}
                        if let Some(map) = vol[VOLUME_TYPE_EMPTY_DIR].as_mapping() {
                            if map.is_empty() {
                                local = true;
                            }
                        }
                    } else if vol.contains_key(VOLUME_TYPE_SECRET) {
                        r#_type = VolumeType::Secret;
                        readonly = true;
                    } else if vol.contains_key(VOLUME_TYPE_CONFIG_MAP) {
                        r#_type = VolumeType::ConfigMap;
                        readonly = true;
                    } else if vol.contains_key(VOLUME_TYPE_DOWNWARD_API) {
                        r#_type = VolumeType::DownwardAPI;
                        readonly = true;
                    } else if vol.contains_key(VOLUME_TYPE_PROJECTED) {
                        r#_type = VolumeType::Projected;
                        readonly = true;
                    } else if vol.contains_key(VOLUME_TYPE_HOST_PATH) {
                        r#_type = VolumeType::HostPath;

                        if let Some(v) = vol[VOLUME_TYPE_HOST_PATH].get("path") {
                            if let Some(path) = v.as_str() {
                                host_path = String::from(path);
                            }
                        }
                    }

                    volumes.insert(
                        String::from(name),
                        Volume {
                            r#_type,
                            readonly,
                            host_path,
                            local,
                        },
                    );
                }
            }
        }

        Ok(volumes)
    }

    pub fn get_debugging(container: &serde_yaml::Value) -> Result<Debugging> {
        let tty = if let Some(v) = container.get("tty") {
            v.as_bool()
                .ok_or_else(|| anyhow!("failed to parse tty into bool"))?
        } else {
            false
        };

        Ok(Debugging { tty })
    }

    pub fn get_env(container: &serde_yaml::Value) -> Result<Vec<String>> {
        let mut results = Vec::new();

        if let Some(env) = container.get("env") {
            let env = env
                .as_sequence()
                .ok_or_else(|| anyhow!("failed to parse env into sequence"))?;

            for map in env {
                let name = map["name"]
                    .as_str()
                    .ok_or_else(|| anyhow!("failed to parse name into string"))?;

                let rule;

                if let Some(v) = map.get("value") {
                    let value = v
                        .as_str()
                        .ok_or_else(|| anyhow!("failed to parse value into string"))?;

                    rule = [name, "=", value].concat();
                } else {
                    (rule, _) = Self::get_value_from(map, name)?;
                }

                results.push(rule);
            }
        }

        Ok(results)
    }

    // Return workingDir, command, and args
    pub fn get_entry_point(
        container: &serde_yaml::Value,
    ) -> Result<(String, Vec<String>, Vec<String>)> {
        let mut working_dir = String::new();
        let mut command = Vec::new();
        let mut args = Vec::new();

        if let Some(v) = container.get("workingDir") {
            working_dir = v
                .as_str()
                .ok_or_else(|| anyhow!("failed to parse workingDir into string"))?
                .to_string();
        }

        if let Some(v) = container.get("command") {
            if let Some(seq) = v.as_sequence() {
                command = seq
                    .iter()
                    .filter_map(|arg| arg.as_str())
                    .map(String::from)
                    .collect::<Vec<_>>();
            }
        }

        if let Some(v) = container.get("args") {
            if let Some(seq) = v.as_sequence() {
                args = seq
                    .iter()
                    .filter_map(|arg| arg.as_str())
                    .map(String::from)
                    .collect::<Vec<_>>();
            }
        };

        Ok((working_dir, command, args))
    }

    pub fn get_mounts(&self, container: &serde_yaml::Value) -> Result<Vec<Mount>> {
        let mut results = Vec::new();

        if let Some(volume_mounts) = container.get("volumeMounts") {
            let volume_mounts = volume_mounts
                .as_sequence()
                .ok_or_else(|| anyhow!("failed to parse volumeMounts into sequence"))?;

            for volume_mount in volume_mounts {
                let destination = volume_mount["mountPath"]
                    .as_str()
                    .ok_or_else(|| anyhow!("failed to prase mountPath into string"))?;

                let destination = PathBuf::from(destination);

                let mut propagation: &str = &String::from("None");
                if let Some(v) = volume_mount.get("mountPropagation") {
                    propagation = v
                        .as_str()
                        .ok_or_else(|| anyhow!("failed to parse mountPropagation into string"))?;
                }

                let name = volume_mount["name"]
                    .as_str()
                    .ok_or_else(|| anyhow!("failed to prase name into string"))?;

                let volume = self
                    .volumes
                    .get(name)
                    .ok_or_else(|| anyhow!("failed to find volume {}", name))?;

                let source = PathBuf::from(&volume.host_path);

                let mut read_only = volume.readonly;
                // Readonly volume takes precedence over the readOnly field
                if !read_only {
                    if let Some(v) = volume_mount.get("readOnly") {
                        read_only = v
                            .as_bool()
                            .ok_or_else(|| anyhow!("failed to parse readOnly into bool"))?;
                    }
                }

                let mut r#type = String::from("bind");

                if volume.local {
                    r#type = String::from("local");
                }

                let mut options: Vec<String> =
                    vec!["rbind"].into_iter().map(String::from).collect();

                match propagation {
                    "None" => {
                        options.push(String::from("rprivate"));
                    }
                    "HostToContainer" => {
                        options.push(String::from("rslave"));
                    }
                    "Bidirectional" => {
                        options.push(String::from("rshared"));
                    }
                    _ => {
                        return Err(anyhow!("Unknown mountPropagation type"));
                    }
                }

                if read_only {
                    options.push(String::from("ro"));
                } else {
                    options.push(String::from("rw"));
                }

                let mut mount = Mount::default();

                mount.set_destination(destination);
                mount.set_typ(Some(r#type));
                mount.set_source(Some(source));
                mount.set_options(Some(options));

                results.push(mount);
            }
        }

        Ok(results)
    }
}

pub fn patch_yaml(yaml: &mut serde_yaml::Value, kind: &str, policy_base64: &str) -> Result<()> {
    let template = match kind {
        "Pod" => yaml
            .as_mapping_mut()
            .ok_or_else(|| anyhow!("failed to parse pod into mapping")),
        "Job" | "Deployment" | "ReplicationController" => yaml["spec"]["template"]
            .as_mapping_mut()
            .ok_or_else(|| anyhow!("failed to parse pod into mapping")),
        _ => {
            bail!("{}: unsupported kind: {}", loc!(), kind);
        }
    }?;

    if template.get("metadata").is_none() {
        let mapping = serde_yaml::Mapping::new();
        template.insert(
            serde_yaml::Value::String("metadata".to_owned()),
            serde_yaml::Value::Mapping(mapping),
        );
    }

    let metadata = template["metadata"]
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("failed to get metadata"))?;

    if metadata.get("annotations").is_none() {
        let mapping = serde_yaml::Mapping::new();
        metadata.insert(
            serde_yaml::Value::String("annotations".to_owned()),
            serde_yaml::Value::Mapping(mapping),
        );
    }

    let annotations = metadata["annotations"]
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("failed to get annotations"))?;

    match annotations.get_mut(CC_POLICY_KEY) {
        Some(value) => {
            *value = serde_yaml::Value::String(String::from(policy_base64));
        }
        None => {
            annotations.insert(
                serde_yaml::Value::String(String::from(CC_POLICY_KEY)),
                serde_yaml::Value::String(String::from(policy_base64)),
            );
        }
    }

    Ok(())
}
