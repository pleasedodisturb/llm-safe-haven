# Fixture Threat Model (Control B -- third-party semver in narrative prose)

Rotate credentials if you are running an affected release of Infisical v0.10.0, or of an
unrelated tool pinned at v0.25.0. Neither mention is a claim about this fixture package's own
version, and neither should ever be compared against `package.json`'s `version` field.
