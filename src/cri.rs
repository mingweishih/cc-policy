// Copyright (c) Cc-Policy Authors.
// Licensed under the Apache 2.0 license.

use anyhow::{anyhow, bail, Result};
use oci_spec::image::ImageConfiguration;
use oci_spec::runtime::{Mount, Process, Spec};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// Default mounts for both sandbox and regular containers
// Reference: https://github.com/containerd/containerd/blob/release/1.6/oci/mounts.go#L26
const DEFAULT_MOUNTS: &str = r#"
[
    {
        "destination": "/proc",
        "source": "^proc$",
        "type": "proc",
        "options": [
            "nosuid",
            "noexec",
            "nodev"
        ]
    },
    {
        "destination": "/dev",
        "source": "^tmpfs$",
        "type": "tmpfs",
        "options": [
            "nosuid",
            "strictatime",
            "mode=755",
            "size=65536k"
        ]
    },
    {
        "destination": "/dev/pts",
        "source": "^devpts$",
        "type": "devpts",
        "options": [
            "nosuid",
            "noexec",
            "newinstance",
            "ptmxmode=0666",
            "mode=0620",
            "gid=5"
        ]
    },
    {
        "destination": "/dev/mqueue",
        "source": "^mqueue$",
        "type": "mqueue",
        "options": [
            "nosuid",
            "noexec",
            "nodev"
        ]
    },
    {
        "destination": "/dev/shm",
        "source": "^/run/kata-containers/sandbox/shm$",
        "type": "bind",
        "options": [
            "rbind"
        ]
    },
    {
        "destination": "/sys",
        "source": "^sysfs$",
        "type": "sysfs",
        "options": [
            "nosuid",
            "noexec",
            "nodev",
            "ro"
        ]
    }
]"#;

fn get_container_rules(privileged: bool, tty: bool) -> Result<Spec> {
    // Default version is based on specs-go
    // Reference:
    // https://github.com/containerd/containerd/blob/release/1.6/oci/spec.go#L139
    // https://github.com/opencontainers/runtime-spec/blob/main/specs-go/version.go#L18
    let mut spec: Spec = serde_json::from_str(
        r#"{
        "ociVersion": "1.0.2-dev"
    }"#,
    )?;

    // Default values are based on populateDefaultUnixSpec
    // Reference: https://github.com/containerd/containerd/blob/release/1.6/oci/spec.go#L143
    let mut process: Process = serde_json::from_str(
        r#"{
        "user": {
            "uid": 0,
            "gid": 0   
        },
        "cwd": "/"
    }"#,
    )?;

    let mut env = Vec::new();

    // Add HOSTNAME env
    // Reference: https://github.com/containerd/containerd/blob/main/pkg/cri/server/container_create_linux.go#L161
    env.push("^HOSTNAME=.+".to_string());

    // Add PATH env
    // Reference: https://github.com/containerd/containerd/blob/main/pkg/cri/server/container_create_linux.go#L141
    env.push("^PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin$".to_string());

    // Add TERM based on tty
    // Reference: https://github.com/containerd/containerd/blob/release/1.6/pkg/cri/server/container_create_linux.go#L151
    if tty {
        env.push("TERM=xterm".to_string());
    }

    process.set_env(Some(env));

    spec.set_process(Some(process));

    let mut mounts: Vec<Mount> = Vec::new();

    // Add default mounts
    // Reference: https://github.com/containerd/containerd/blob/release/1.6/oci/mounts.go#L26
    let default_mounts: Vec<Mount> = serde_json::from_str(DEFAULT_MOUNTS)?;

    mounts.extend(default_mounts);

    // Add readonly cgroup
    // Reference: https://github.com/containerd/containerd/blob/release/1.6/pkg/cri/opts/spec_linux.go#L122
    mounts.push(serde_json::from_str(
        r#"
    {
        "destination": "/sys/fs/cgroup",
        "source": "^cgroup$",
        "type": "cgroup",
        "options": [
            "nosuid",
            "noexec",
            "nodev",
            "relatime",
            "ro"
        ]
    }
    "#,
    )?);

    // Add /etc/hostname, /etc/hosts, and /etc/resolv.conf
    // Reference: https://github.com/containerd/containerd/blob/release/1.6/pkg/cri/server/container_create_linux.go#L60
    // TODO: Add "rw" or "ro" based on securityContext.readOnlyRootFilesystem
    // Note that the function also adds /dev/shm, which is ignored given that the default rules already include it
    let container_mounts: Vec<Mount> = serde_json::from_str(
        r#"
    [
        {
            "destination": "/etc/hostname",
            "source": "^/run/kata-containers/shared/containers/[a-z0-9]+-[a-z0-9]+-hostname$",
            "type": "bind",
            "options": [
                "rbind",
                "rprivate",
                "rw"
            ]
        },
        {
            "destination": "/etc/hosts",
            "source": "^/run/kata-containers/shared/containers/[a-z0-9]+-[a-z0-9]+-hosts$",
            "type": "bind",
            "options": [
                "rbind",
                "rprivate",
                "rw"
            ]
        },
        {
            "destination": "/etc/resolv.conf",
            "source": "^/run/kata-containers/shared/containers/[a-z0-9]+-[a-z0-9]+-resolv.conf$",
            "type": "bind",
            "options": [
                "rbind",
                "rprivate",
                "rw"
            ]
        }
    ]
    "#,
    )?;

    mounts.extend(container_mounts);

    if privileged {
        for mount in &mut mounts {
            let r#type = mount
                .typ()
                .as_ref()
                .ok_or_else(|| anyhow!("failed to get mount type"))?
                .clone();

            // Reference: https://github.com/containerd/containerd/blob/release/1.6/oci/spec_opts.go#L971
            if r#type == "sysfs" {
                let mut options = mount
                    .options()
                    .as_ref()
                    .ok_or_else(|| anyhow!("failed to get options"))?
                    .clone();
                options.iter_mut().for_each(|option| {
                    if option == "ro" {
                        *option = "rw".to_string()
                    }
                });
                mount.set_options(Some(options));
            }

            // Reference: https://github.com/containerd/containerd/blob/release/1.6/oci/spec_opts.go#L985
            if r#type == "cgroup" {
                let mut options = mount
                    .options()
                    .as_ref()
                    .ok_or_else(|| anyhow!("failed to get options"))?
                    .clone();
                options.iter_mut().for_each(|option| {
                    if option == "ro" {
                        *option = "rw".to_string()
                    }
                });
                mount.set_options(Some(options));
            }
        }
    }

    spec.set_mounts(Some(mounts));

    Ok(spec)
}

fn get_sandbox_rules(privileged: bool, tty: bool) -> Result<Spec> {
    // Default version is based on specs-go
    // Reference:
    // https://github.com/containerd/containerd/blob/release/1.6/oci/spec.go#L139
    // https://github.com/opencontainers/runtime-spec/blob/main/specs-go/version.go#L18
    let mut spec: Spec = serde_json::from_str(
        r#"{
        "ociVersion": "1.0.2-dev"
    }"#,
    )?;

    // Default values are based on populateDefaultUnixSpec
    // Reference: https://github.com/containerd/containerd/blob/release/1.6/oci/spec.go#L143
    let mut process: Process = serde_json::from_str(
        r#"{
        "user": {
            "uid": 0,
            "gid": 0   
        },
        "cwd": "/"
    }"#,
    )?;

    let mut env = Vec::new();

    // TODO: Double check if the there is a way to set tty for the sandbox container
    // Add TERM based on tty
    // Reference: https://github.com/containerd/containerd/blob/release/1.6/pkg/cri/server/container_create_linux.go#L151
    if tty {
        env.push("TERM=xterm".to_string());
    }

    process.set_env(Some(env));

    spec.set_process(Some(process));

    let mut mounts: Vec<Mount> = Vec::new();

    // Add default mounts
    let default_mounts: Vec<Mount> = serde_json::from_str(DEFAULT_MOUNTS)?;

    mounts.extend(default_mounts);

    // Reference: https://github.com/containerd/containerd/blob/release/1.6/pkg/cri/server/sandbox_run_linux.go#L111
    mounts.push(serde_json::from_str(
        r#"
    {
        "destination": "/etc/resolv.conf",
        "source": "^/run/kata-containers/shared/containers/[a-z0-9]+-[a-z0-9]+-resolv.conf$",
        "type": "bind",
        "options": [
            "rbind",
            "ro"
        ]
    }
    "#,
    )?);

    // TODO: Double check if the there is a way to set privileged for the sandbox container
    if privileged {
        for mount in &mut mounts {
            let r#type = mount
                .typ()
                .as_ref()
                .ok_or_else(|| anyhow!("failed to get mount type"))?
                .clone();

            // Reference: https://github.com/containerd/containerd/blob/release/1.6/oci/spec_opts.go#L971
            if r#type == "sysfs" {
                let mut options = mount
                    .options()
                    .as_ref()
                    .ok_or_else(|| anyhow!("failed to get options"))?
                    .clone();
                options.iter_mut().for_each(|option| {
                    if option == "ro" {
                        *option = "rw".to_string()
                    }
                });
                mount.set_options(Some(options));
            }

            // TODO: Check why sandbox does not have the /sys/fs/cgroup mount
        }
    }

    spec.set_mounts(Some(mounts));

    Ok(spec)
}

pub fn get_rules(is_sandbox: bool, privileged: bool, tty: bool) -> Result<Spec> {
    if !is_sandbox {
        get_container_rules(privileged, tty)
    } else {
        get_sandbox_rules(privileged, tty)
    }
}

// Based on the logic of WithProcessArgs
// https://github.com/containerd/containerd/blob/release/1.6/pkg/cri/opts/spec.go#L55
pub fn merge_process_args(
    container_command: &[String],
    container_args: &[String],
    image_config: &ImageConfiguration,
) -> Result<Vec<String>> {
    let (image_cmd, image_entrypoint) = if let Some(config) = image_config.config() {
        let cmd = if let Some(cmd) = config.cmd() {
            cmd.clone()
        } else {
            Vec::new()
        };

        let entrypoint = if let Some(entrypoint) = config.entrypoint() {
            entrypoint.clone()
        } else {
            Vec::new()
        };

        (cmd, entrypoint)
    } else {
        (Vec::new(), Vec::new())
    };

    let mut args = container_args.to_vec();
    let mut command = container_command.to_vec();

    if container_command.is_empty() {
        if container_args.is_empty() {
            args.extend(image_cmd);
        }

        if !(image_entrypoint.len() == 1 && image_entrypoint[0].is_empty()) {
            command.extend(image_entrypoint);
        }
    }

    if command.is_empty() && args.is_empty() {
        bail!("no command specified");
    }

    Ok([command, args].concat())
}

// Overwritten logic is based on
// https://github.com/containerd/containerd/blob/release/1.6/pkg/cri/server/container_create_linux.go#L144
pub fn merge_process_cwd(
    container_working_dir: &str,
    image_config: &ImageConfiguration,
) -> Result<PathBuf> {
    let image_working_dir = if let Some(config) = image_config.config() {
        if let Some(working_dir) = config.working_dir() {
            working_dir.to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    if !container_working_dir.is_empty() {
        Ok(PathBuf::from(container_working_dir))
    } else if !image_working_dir.is_empty() {
        Ok(PathBuf::from(image_working_dir))
    } else {
        Ok(PathBuf::new())
    }
}

// The following logic is based on replaceOrAppendEnvValues
// https://github.com/containerd/containerd/blob/release/1.6/oci/spec_opts.go#L178
pub fn merge_process_env(defaults: &mut Vec<String>, overrides: &[String]) -> Result<()> {
    let mut cache = HashMap::new();

    for (index, env) in defaults.iter_mut().enumerate() {
        let eqpos = env.find('=').unwrap();
        let (name, _) = env.split_at(eqpos);

        *cache.entry(name.to_string()).or_insert_with(|| 0) = index;
    }

    let mut removes = Vec::new();

    for env in overrides.iter() {
        if let Some(eqpos) = env.find('=') {
            let (name, _) = env.split_at(eqpos);

            if let Entry::Occupied(entry) = cache.entry(name.to_string()) {
                let index = entry.get();
                defaults[index.to_owned()] = env.to_string();
            } else {
                defaults.push(env.to_string())
            }
        } else {
            // Values with out '=' indicates the env should be removed
            removes.push(env.to_string());
        }
    }

    // TODO: Check the case of removing two variables with the same key in a list
    for remove in removes {
        if let Entry::Occupied(entry) = cache.entry(remove) {
            let index = entry.get();
            defaults.remove(index.to_owned());
        }
    }

    Ok(())
}

pub fn get_image_volume_mounts(image_config: &ImageConfiguration) -> Result<Vec<Mount>> {
    let mut mounts = Vec::new();

    if let Some(config) = image_config.config() {
        if let Some(volumes) = config.volumes() {
            volumes.iter().for_each(|volume| {
                let path = Path::new(volume);
                let file_name = path.file_name().unwrap();
                let file_name = file_name.to_str().unwrap();

                let mut mount = Mount::default();

                mount.set_destination(PathBuf::from(volume.to_string()));
                mount.set_source(Some(PathBuf::from(
                    [
                        "^/run/kata-containers/shared/containers/[a-z0-9]+-[a-z0-9]+-",
                        file_name,
                        "$",
                    ]
                    .concat(),
                )));
                mount.set_typ(Some(String::from("bind")));
                mount.set_options(Some(
                    vec!["rbind", "rprivate", "rw"]
                        .into_iter()
                        .map(String::from)
                        .collect(),
                ));

                mounts.push(mount);
            });
        }
    }

    Ok(mounts)
}

// The following logic is based on
// https://github.com/containerd/containerd/blob/release/1.6/pkg/cri/opts/spec_linux.go#L95
pub fn merge_mounts(mounts: &[Mount], extras: &[Mount]) -> Result<Vec<Mount>> {
    let mut results = HashMap::new();

    // Rule:
    // - mounts takes precedence over extras if two mount points share the same destination
    // - mount point comes later in the list takes precedence previous ones that share the same
    //   destination
    // TODO: Check how CRI handles mount points with the same destination in the same list

    extras.iter().for_each(|mount| {
        *results
            .entry(mount.destination().as_os_str())
            .or_insert_with(|| Mount::default()) = mount.clone();
    });

    mounts.iter().for_each(|mount| {
        *results
            .entry(mount.destination().as_os_str())
            .or_insert_with(|| Mount::default()) = mount.clone();
    });

    Ok(results.values().cloned().collect())
}
