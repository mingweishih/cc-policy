use anyhow::{bail, Context, Result};
use oci_spec::image::ImageConfiguration;
use std::process::Command;

const SKOPEO: &str = "skopeo";
const DOCKER_URI_PREFIX: &str = "docker://";
const DOCKER_RESGISTRY_PREFIX: &str = "docker.io/library/";

pub fn pull_image_config(image_ref: &str) -> Result<ImageConfiguration> {
    let image_uri = match image_ref.rfind("://") {
        Some(_) => image_ref.to_owned(),
        None => match image_ref.rfind('/') {
            Some(_) => [DOCKER_URI_PREFIX, image_ref].concat(),
            None => [DOCKER_URI_PREFIX, DOCKER_RESGISTRY_PREFIX, image_ref].concat(),
        },
    };

    let output = Command::new(SKOPEO)
        .arg("inspect")
        .arg(&image_uri)
        .arg("--config")
        .output()
        .context(loc!())?;

    let config = String::from_utf8_lossy(&output.stdout);

    if config.is_empty() {
        bail!(
            "{}: failed to get image config with the uri {}",
            loc!(),
            image_uri
        );
    }

    let image_config: ImageConfiguration = serde_json::from_str(&config).context(loc!())?;

    Ok(image_config)
}

pub fn get_env(image_config: &ImageConfiguration) -> Result<Vec<String>> {
    let mut results = Vec::new();

    // Surround the env with ^ and $ to comply the regex syntax
    if let Some(config) = image_config.config() {
        if let Some(image_envs) = config.env() {
            results = image_envs
                .iter()
                .map(|env| ["^", env, "$"].concat())
                .collect();
        }
    }

    Ok(results)
}
