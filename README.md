# Changelog Action

This GitHub Action generates a changelog between two container image versions by inspecting their package lists (RPMs) using `skopeo` and verifying attestation with `cosign`.

It supports both explicit tag comparison and automatic tag discovery based on a release stream (e.g., `stable`, `latest`).

## Usage

```yaml
- name: Generate Changelog
  uses: hanthor/changelog-action@v1
  with:
    registry: ghcr.io/ublue-os/
    cosign-key: https://raw.githubusercontent.com/ublue-os/bluefin/main/cosign.pub
    images: bluefin bluefin-dx
    stream: stable
    output: changelog.md
```

## Inputs

| Input | Description | Required | Default |
| --- | --- | --- | --- |
| `registry` | Container registry URL | Yes | `ghcr.io/ublue-os/` |
| `cosign-key` | URL or path to cosign public key | Yes | |
| `images` | Space-separated list of image names | Yes | |
| `stream` | Release stream for auto-discovery (e.g. `stable`, `latest`) | No | |
| `prev-tag` | Previous release tag (ignored if `stream` is set) | No | |
| `curr-tag` | Current release tag (ignored if `stream` is set) | No | |
| `handwritten` | Optional introductory text for the changelog | No | |
| `output` | Output file path | No | `changelog.md` |
| `output-env` | Output environment file path (TITLE=... TAG=...) | No | |
| `json` | Output JSON instead of Markdown | No | `false` |
| `verbose` | Enable debug logging | No | `false` |
