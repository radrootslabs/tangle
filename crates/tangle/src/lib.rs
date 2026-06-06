#![forbid(unsafe_code)]

pub const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn version_output() -> String {
    format!("{PACKAGE_NAME} {PACKAGE_VERSION}")
}

#[cfg(test)]
mod tests {
    use super::{PACKAGE_NAME, PACKAGE_VERSION, version_output};

    #[test]
    fn package_name_is_tangle() {
        assert_eq!(PACKAGE_NAME, "tangle");
    }

    #[test]
    fn package_version_matches_manifest() {
        assert_eq!(PACKAGE_VERSION, "0.1.0");
    }

    #[test]
    fn version_output_contains_package_and_version() {
        assert_eq!(version_output(), "tangle 0.1.0");
    }
}
