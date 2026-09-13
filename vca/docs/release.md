# How to cut a release

A git tag is the only path to a published release (ADR-006 decision 3).
One tag releases every service, the CLI and the Helm charts at the same
version (ADR-006 decision 4).

## Before you tag

1. Make sure `main` is green in `vca-ci` and the last `vca-nightly` run passed.
2. Choose the next version with SemVer 2.0.0. Read the commits since the
   last tag:

   ```sh
   last=$(git tag --list 'v*' --sort=-v:refname | head -1)
   vca/hack/release-notes.sh "$last" HEAD
   ```

   - A `BREAKING CHANGE` footer or a `!` after the type bumps the major version.
   - A `feat` commit bumps the minor version.
   - A `fix` commit bumps the patch version.
   - Before `v1.0.0`, a breaking change bumps the minor version.

3. Do not edit a CHANGELOG file by hand. The release workflow generates the
   notes from the commits.

## Tag and push

```sh
git checkout main
git pull --ff-only
git tag vX.Y.Z
git push --tags
```

Use an annotated tag when you want a message:

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The push starts `.github/workflows/vca-release.yml`.

## What the workflow publishes

- Images `ghcr.io/<owner>/vca-<service>:vX.Y.Z`, `:vX.Y` and `:vX` for every
  service under `vca/services/*/` with a `Dockerfile`. Cosign signs each
  image. Each image carries SPDX and CycloneDX SBOM attestations.
- A GitHub Release named `vX.Y.Z` with the generated notes and these files:
  `vca_vX.Y.Z_<os>_<arch>` binaries with `.sha256` checksums, `*.tgz` Helm
  chart packages, `*.spdx.json` and `*.cdx.json` SBOM files, and one
  `.digest` file per image.

## Pre-releases

A tag such as `v1.2.0-rc.1` publishes the `:v1.2.0-rc.1` image tag only.
The floating `:v1.2` and `:v1` tags do not move. The GitHub Release is
marked as a pre-release.

## Check a published image

```sh
ref=ghcr.io/<owner>/vca-<service>@sha256:<digest>
cosign verify \
  --certificate-identity-regexp '^https://github.com/<owner>/verifiably/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ref"
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp '^https://github.com/<owner>/verifiably/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ref" | jq -r .payload | base64 -d | jq .predicate
```

## Fix a bad release

Do not move or delete a pushed tag. Fix the problem on `main`,
then tag the next patch version.
