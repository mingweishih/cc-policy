// Copyright (c) Cc-Policy Authors.
// Licensed under the Apache 2.0 license.

use crate::cri;
use crate::cri::*;
use crate::image;
use crate::image::pull_image_config;
use crate::kubernetes;
use crate::kubernetes::*;
use crate::oci::*;
use crate::PodYaml;

use anyhow::{anyhow, Context, Result};
use oci_spec::image::ImageConfiguration;
use oci_spec::runtime::Spec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

const CC_POLICY_VERSION: &str = "0.1.0";

#[derive(Serialize, Deserialize)]
pub struct Custom {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ContainerPolicy {
    pub oci_spec: Spec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<Custom>,
}

#[derive(Serialize, Deserialize)]
pub struct CcPolicy {
    version: String,
    containers: HashMap<String, ContainerPolicy>,
}

impl CcPolicy {
    pub fn new() -> CcPolicy {
        let version = String::from(CC_POLICY_VERSION);
        let containers = HashMap::new();

        CcPolicy {
            version,
            containers,
        }
    }

    fn get_container_policy(
        &mut self,
        pod_yaml: &PodYaml,
        containers: &Vec<serde_yaml::Value>,
        with_default_rules: bool,
    ) -> Result<()> {
        for container in containers {
            let name = PodYaml::get_name(container)?;
            let container_policy =
                ContainerPolicy::from_container_yaml(container, pod_yaml, with_default_rules)?;

            self.containers.insert(name, container_policy);
        }

        if with_default_rules {
            let sandbox_policy = ContainerPolicy::create_sandbox_policy()?;

            self.containers
                .insert(KUBERNETES_PAUSE_NAME.to_string(), sandbox_policy);
        }

        Ok(())
    }

    pub fn from_pod_yaml(pod_yaml: &PodYaml, with_default_rules: bool) -> Result<CcPolicy> {
        let mut cc_policy = CcPolicy::new();

        if let Some(containers) = pod_yaml.containers {
            cc_policy.get_container_policy(pod_yaml, containers, with_default_rules)?;
        }

        if let Some(init_containers) = pod_yaml.init_containers {
            cc_policy.get_container_policy(pod_yaml, init_containers, with_default_rules)?;
        }

        Ok(cc_policy)
    }

    pub fn from_image_ref(image_ref: &str, with_default_rules: bool) -> Result<CcPolicy> {
        let mut cc_policy = CcPolicy::new();

        let name = match image_ref.find(':') {
            Some(index) => {
                let (name, _) = image_ref.split_at(index);
                name
            }
            None => image_ref,
        };

        let container_policy = ContainerPolicy::from_image_ref(image_ref, with_default_rules)?;

        cc_policy
            .containers
            .insert(name.to_owned(), container_policy);

        Ok(cc_policy)
    }

    pub fn to_base64(&self) -> String {
        let json = self.to_string();

        base64::encode(&json)
    }
}

impl fmt::Display for CcPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(&self).unwrap())
    }
}

impl ContainerPolicy {
    pub fn from_container_yaml(
        container: &serde_yaml::Value,
        pod_yaml: &PodYaml,
        with_default_rules: bool,
    ) -> Result<ContainerPolicy> {
        let security_context = PodYaml::get_security_context(container)?;
        let debugging = PodYaml::get_debugging(container)?;
        let mut oci_spec = if with_default_rules {
            cri::get_rules(false, security_context.privileged, debugging.tty)?
        } else {
            empty_spec()?
        };
        let kube_rules = kubernetes::get_rules(false)?;
        let image_name = container["image"]
            .as_str()
            .ok_or_else(|| anyhow!("failed to parse image into string"))?;
        let layers = Vec::new();
        let image_config = pull_image_config(image_name)?;
        //let allow_elevated = security_context.allow_elevated;

        Self::get_process(&mut oci_spec, container, &image_config, &kube_rules)?;

        Self::get_mounts(
            &mut oci_spec,
            Some(pod_yaml),
            container,
            &image_config,
            &kube_rules,
        )?;

        let custom = Some(Custom { layers });

        Ok(ContainerPolicy { oci_spec, custom })
    }

    pub fn from_image_ref(image_ref: &str, with_default_rules: bool) -> Result<ContainerPolicy> {
        let layers = Vec::new();
        let image_config = pull_image_config(image_ref).context(loc!())?;

        let mut oci_spec = if with_default_rules {
            cri::get_rules(false, false, false)?
        } else {
            empty_spec()?
        };

        let container = serde_yaml::Value::Null;

        let empty_spec = empty_spec()?;

        Self::get_process(&mut oci_spec, &container, &image_config, &empty_spec).context(loc!())?;

        Self::get_mounts(&mut oci_spec, None, &container, &image_config, &empty_spec)
            .context(loc!())?;

        let custom = Some(Custom { layers });

        Ok(ContainerPolicy { oci_spec, custom })
    }

    pub fn create_sandbox_policy() -> Result<ContainerPolicy> {
        let mut oci_spec = cri::get_rules(true, false, false)?;
        let layers = Vec::new();

        let image_ref = get_pause_image_ref();

        let image_config = pull_image_config(&image_ref)?;

        let container = serde_yaml::Value::Null;

        let empty_spec = empty_spec()?;

        Self::get_process(&mut oci_spec, &container, &image_config, &empty_spec)?;

        Self::get_mounts(&mut oci_spec, None, &container, &image_config, &empty_spec)?;

        let custom = Some(Custom { layers });

        Ok(ContainerPolicy { oci_spec, custom })
    }

    fn get_env(
        spec: &Spec,
        container: &serde_yaml::Value,
        image_config: &ImageConfiguration,
        kube_rules: &Spec,
    ) -> Result<Vec<String>> {
        // Override rule: the latter variables will override the former ones with the same name
        // Order based on the CRI:
        // - CRI default variables
        // - HOSTNAME
        // - Variables from Image Config
        // - Variables from Kubernetes
        // - Variables from Pod YAML
        let mut results = Vec::new();

        if let Some(process) = spec.process() {
            if let Some(envs) = process.env() {
                results = envs.clone();
            }
        }

        let mut kube_envs = Vec::new();

        if let Some(process) = kube_rules.process() {
            if let Some(envs) = process.env() {
                kube_envs = envs.clone();
            }
        }

        merge_process_env(&mut results, &kube_envs)?;

        let image_envs = image::get_env(image_config)?;

        merge_process_env(&mut results, &image_envs)?;

        let yaml_envs = PodYaml::get_env(container)?;

        merge_process_env(&mut results, &yaml_envs)?;

        Ok(results)
    }

    fn get_process(
        spec: &mut Spec,
        container: &serde_yaml::Value,
        image_config: &ImageConfiguration,
        kube_rules: &Spec,
    ) -> Result<()> {
        let (working_dir, command, args) = PodYaml::get_entry_point(container)?;

        // Make a copy given that Spec does not support mutable getter
        let mut process = if let Some(process) = spec.process() {
            process.clone()
        } else {
            empty_process()?
        };

        let args = merge_process_args(&command, &args, image_config)?;

        let cwd = merge_process_cwd(&working_dir, image_config)?;

        // Overwrite the default cwd if the working_dir from either pod yaml or image config is not empty.
        // Reference
        // https://github.com/containerd/containerd/blob/release/1.6/pkg/cri/server/container_create_linux.go#L144
        // https://github.com/containerd/containerd/blob/main/oci/spec_opts.go#L234
        if !cwd.as_os_str().is_empty() {
            process.set_cwd(cwd);
        }

        let env = Self::get_env(spec, container, image_config, kube_rules)?;

        process.set_args(Some(args));
        process.set_env(Some(env));

        spec.set_process(Some(process));

        Ok(())
    }

    fn get_mounts(
        spec: &mut Spec,
        pod_yaml: Option<&PodYaml>,
        container: &serde_yaml::Value,
        image_config: &ImageConfiguration,
        kube_rules: &Spec,
    ) -> Result<()> {
        let pod_mounts = if let Some(pod_yaml) = pod_yaml {
            pod_yaml.get_mounts(container)?
        } else {
            Vec::new()
        };

        // Order based on OCI:
        // - Volumes from pod yaml
        // - Mounts inserted by Kubelet
        // - Image volumes
        // - Default mounts
        let image_volumes = get_image_volume_mounts(image_config)?;

        let results = if let Some(kube_mounts) = kube_rules.mounts() {
            merge_mounts(&pod_mounts, kube_mounts)?
        } else {
            pod_mounts
        };

        let results = merge_mounts(&results, &image_volumes)?;

        let results = if let Some(default_mounts) = spec.mounts() {
            merge_mounts(&results, default_mounts)?
        } else {
            results
        };

        spec.set_mounts(Some(results));

        Ok(())
    }
}
