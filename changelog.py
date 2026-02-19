#!/usr/bin/env python3

import sys
import json
import subprocess
import time
import re
import base64
import argparse
import logging
import zstandard as zstd
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

# ----------------------------------------------------------------------------
# Defaults / Constants
# ----------------------------------------------------------------------------

FEATURED_PACKAGES = {
    "kernel": "kernel",
    "gnome": "gnome-shell",
    "mesa": "mesa",
    "podman": "podman",
    "nvidia": "akmod-nvidia",
    "docker": "docker",
    "systemd": "systemd",
    "bootc": "bootc"
}

VARIANT_LABELS = {
    "stable": "Stable Release",
    "lts":    "LTS Release",
    "gts":    "GTS Release",
    "beta":   "Beta Release",
}

RETRIES = 3
RETRY_WAIT_S = 2.0

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# ----------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------

def run_cmd(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout
    else:
        raise Exception(f"Command failed\nCmd: {cmd}\nExit: {result.returncode}\nErr: {result.stderr}")

def retry(n: int, f: Callable) -> any:
    for attempt in range(1, n + 1):
        try:
            return f()
        except Exception as e:
            if attempt < n:
                log.warning(f"Attempt {attempt}/{n} failed: {e}. Retrying in {RETRY_WAIT_S}s…")
                time.sleep(RETRY_WAIT_S)
            else:
                raise

# ----------------------------------------------------------------------------
# SBOM Fetching
# ----------------------------------------------------------------------------

def get_digest(registry: str, image: str, tag: str) -> str:
    reg = registry if registry.endswith('/') else f"{registry}/"
    uri = f"docker://{reg}{image}:{tag}"
    
    # 1. Fetch raw manifest to check if it's a manifest list (index)
    def _fetch_raw():
        return run_cmd(["skopeo", "inspect", "--raw", uri])
    
    try:
        raw_out = retry(RETRIES, _fetch_raw)
        data = json.loads(raw_out)
        
        # OCI Image Index or Docker Manifest List
        if "manifests" in data:
            log.info(f"Detected manifest list for {image}:{tag}. Resolving for linux/amd64.")
            for m in data["manifests"]:
                p = m.get("platform", {})
                if p.get("os") == "linux" and p.get("architecture") == "amd64":
                    return m["digest"]
            
            # Fallback if no amd64 found (unlikely for Bluefin)
            log.warning("No linux/amd64 manifest found in index. Using the first manifest.")
            return data["manifests"][0]["digest"]
            
    except Exception as e:
        log.warning(f"Failed to inspect raw manifest for {image}:{tag}: {e}")

    # 2. If not a list or raw fetch failed, fall back to standard inspect
    def _fetch_digest():
        return run_cmd(["skopeo", "inspect", "--format", "{{.Digest}}", uri]).strip()
        
    return retry(RETRIES, _fetch_digest)

def extract_payloads(s: str) -> list[str]:
    # Regex to extract 'payload' from JSON lines in cosign output
    return re.findall(r'"payload"\s*:\s*"([^"]+)"', s)

def fetch_sbom(registry: str, cosign_key: str, image: str, digest: str) -> dict:
    def _fetch():
        reg = registry if registry.endswith('/') else f"{registry}/"
        cmd = [
            "cosign", "verify-attestation",
            # We remove --type spdxjson to fetch all attestations and manually filter/decode
            "--key", cosign_key,
            f"{reg}{image}@{digest}"
        ]
        raw = run_cmd(cmd)

        payloads = extract_payloads(raw)
        if not payloads:
            raise ValueError("No payload found in attestation output.")

        for payload_b64 in payloads:
            try:
                payload_bytes = base64.b64decode(payload_b64)
                payload_json = json.loads(payload_bytes.decode("utf-8"))
                
                predicate_type = payload_json.get("predicateType")
                predicate = payload_json.get("predicate", {})

                # Handle standard SPDX JSON
                if predicate_type in ["https://spdx.dev/Document", "spdxjson", "application/spdx+json"]:
                     if predicate.get("packages") or predicate.get("artifacts"):
                         return predicate
                
                # Handle Bluefin zstd compressed SBOM
                if predicate_type == "urn:ublue-os:attestation:spdx+json+zstd:v1":
                    # For this type, predicate is a base64 encoded string of zstd compressed JSON
                    if isinstance(predicate, str):
                        zstd_bytes = base64.b64decode(predicate)
                        dctx = zstd.ZstdDecompressor()
                        decompressed = dctx.decompress(zstd_bytes)
                        sbom = json.loads(decompressed)
                        if sbom.get("packages") or sbom.get("artifacts"):
                            return sbom
                    elif isinstance(predicate, dict) and predicate.get("compression") == "zstd":
                        # Handle case where predicate is object wrapping payload
                        raw_payload = predicate.get("payload")
                        if raw_payload:
                            zstd_bytes = base64.b64decode(raw_payload)
                            dctx = zstd.ZstdDecompressor()
                            decompressed = dctx.decompress(zstd_bytes)
                            sbom = json.loads(decompressed)
                            if sbom.get("packages") or sbom.get("artifacts"):
                                return sbom

            except Exception as e:
                log.warning(f"Skipping payload that failed to decode: {e}")
                continue

        raise ValueError("No valid SPDX predicate found among attestation payloads.")

    return retry(RETRIES, _fetch)

# ----------------------------------------------------------------------------
# Package Extraction
# ----------------------------------------------------------------------------

EPOCH_PATTERN = re.compile(r"^\d+:")
FEDORA_PATTERN = re.compile(r"\.fc\d+")

def normalize_version(v: str) -> str:
    v = EPOCH_PATTERN.sub("", v)
    v = FEDORA_PATTERN.sub("", v)
    return v

def parse_packages(sbom: dict) -> dict:
    pkg_map = {}
    for artifact in sbom.get("artifacts", []):
        if artifact.get("type") == "rpm":
            name = artifact.get("name")
            version = artifact.get("version")
            if name and version:
                pkg_map[name] = normalize_version(version)
            else:
                log.debug(f"Skipping malformed artifact: {artifact}")
    return dict(sorted(pkg_map.items()))

def fetch_packages(registry: str, cosign_key: str, image: str, tag: str) -> dict:
    digest = get_digest(registry, image, tag)
    log.info(f"Resolved {image}:{tag} to {digest}")
    sbom = fetch_sbom(registry, cosign_key, image, digest)
    return parse_packages(sbom)

def build_release(registry: str, cosign_key: str, images: list[str], tag: str) -> dict:
    results = {}
    def _fetch_one(img):
        log.info(f"Fetching packages for {img}:{tag}…")
        return img, fetch_packages(registry, cosign_key, img, tag)

    with ThreadPoolExecutor(max_workers=len(images)) as executor:
        futures = {executor.submit(_fetch_one, img): img for img in images}
        for future in as_completed(futures):
            img, pkgs = future.result()
            results[img] = {"packages": pkgs}
    return results

# ----------------------------------------------------------------------------
# Tag Discovery
# ----------------------------------------------------------------------------

def get_tag_list(registry: str, image: str, tag: str) -> list[str]:
    # Don't resolve index when listing tags, just in case overrides affect RepoTags availability
    manifest = fetch_manifest(registry, image, tag, resolve_index=False)
    tags = manifest.get("RepoTags", [])
    log.info(f"Fetched manifest keys: {list(manifest.keys())}")
    log.info(f"Found {len(tags)} tags.")
    return tags

def discover_tags(registry: str, image: str, stream: str) -> tuple[str, str]:
    log.info(f"Discovering tags for {image} {stream}...")
    tags = get_tag_list(registry, image, stream)
    
    pattern = re.compile(rf"^{stream}-(?:\\d+\\.)?\\d{{8}}(?:\\.\\d+)?$")
    filtered_tags = sorted([t for t in tags if pattern.match(t)])
    
    if len(filtered_tags) < 2:
        raise ValueError(f"Found fewer than 2 tags matching pattern for {stream}. Found: {filtered_tags}")
        
    return filtered_tags[-2], filtered_tags[-1]

# ----------------------------------------------------------------------------
# Diff Logic
# ----------------------------------------------------------------------------

def diff_packages(prev_pkgs: dict, curr_pkgs: dict) -> dict:
    prev_keys = set(prev_pkgs.keys())
    curr_keys = set(curr_pkgs.keys())

    added = {k: curr_pkgs[k] for k in curr_keys - prev_keys}
    removed = {k: prev_pkgs[k] for k in prev_keys - curr_keys}
    changed = {
        k: {"from": prev_pkgs[k], "to": curr_pkgs[k]}
        for k in prev_keys & curr_keys if prev_pkgs[k] != curr_pkgs[k]
    }

    return {
        "added": dict(sorted(added.items())),
        "removed": dict(sorted(removed.items())),
        "changed": dict(sorted(changed.items()))
    }

def diff_images(prev_release: dict, curr_release: dict) -> dict:
    result = {}
    for img, curr_data in curr_release.items():
        prev_pkgs = prev_release.get(img, {}).get("packages", {})
        result[img] = diff_packages(prev_pkgs, curr_data["packages"])
    return result

def common_packages(release: dict) -> list:
    if not release:
        return []
    package_sets = [set(data["packages"].keys()) for data in release.values()]
    return sorted(set.intersection(*package_sets))

# ----------------------------------------------------------------------------
# Git Commits (Optional, requires local clone usually)
# ----------------------------------------------------------------------------

def fetch_commits(prev_tag: str, curr_tag: str) -> list[dict]:
    try:
        # Check if we are inside a git repo
        subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], check=True, capture_output=True)
        out = run_cmd(["git", "log", "--pretty=format:%H;%s;%an", f"{prev_tag}..{curr_tag}"])
    except Exception as e:
        log.warning(f"Could not fetch git commits (might not be a git repo or tags missing): {e}")
        return []

    commits = []
    for line in out.strip().splitlines():
        if line:
            parts = line.split(";", 2)
            if len(parts) == 3:
                commits.append({"hash": parts[0], "subject": parts[1], "author": parts[2]})
    return commits

# ----------------------------------------------------------------------------
# Markdown Generation
# ----------------------------------------------------------------------------

def infer_variant_label(tag: str) -> str:
    prefix = tag.split("-")[0].lower()
    return VARIANT_LABELS.get(prefix, f"{prefix.upper()} Release")

def render_changelog(data: dict, handwritten: str = "") -> str:
    prev_tag = data["prev-tag"]
    curr_tag = data["curr-tag"]
    variant_label = infer_variant_label(curr_tag)

    lines = [
        f"# 🦕 {curr_tag}: {variant_label}",
        ""
    ]
    if handwritten:
        lines.append(handwritten)
        lines.append("")

    lines.extend([
        f"This is an automatically generated changelog for release `{curr_tag}`.",
        "",
        f"From previous version `{prev_tag}` there have been the following changes.",
        ""
    ])

    for img, pkg_diff in data["diff"].items():
        lines.append(f"## 📦 {img} Packages")
        lines.append("")

        if pkg_diff.get("added"):
            lines.append("### ✨ Added")
            lines.append("| Package | Version |")
            lines.append("| --- | --- |")
            for name, version in pkg_diff["added"].items():
                lines.append(f"| {name} | {version} |")
            lines.append("")

        if pkg_diff.get("removed"):
            lines.append("### ❌ Removed")
            lines.append("| Package | Version |")
            lines.append("| --- | --- |")
            for name, version in pkg_diff["removed"].items():
                lines.append(f"| {name} | {version} |")
            lines.append("")

        if pkg_diff.get("changed"):
            lines.append("### 🔄 Changed")
            lines.append("| Package | Version |")
            lines.append("| --- | --- |")
            for name, changes in pkg_diff["changed"].items():
                lines.append(f"| {name} | {changes['from']} ➡️ {changes['to']} |")
            lines.append("")

    commits = data.get("commits", [])
    if commits:
        lines.append("## 📜 Commits")
        lines.append("| Hash | Subject | Author |")
        lines.append("| --- | --- | --- |")
        for commit in commits:
            short_hash = commit["hash"][:7]
            # Assumes GitHub URL structure based on remote origin if possible, otherwise generic
            lines.append(f"| 🔹 **{short_hash}** | {commit['subject']} | {commit['author']} |")
        lines.append("")

    return "\n".join(lines)


def build_release_data(
    registry: str,
    cosign_key: str,
    images: list[str],
    prev_tag: str,
    curr_tag: str,
) -> dict:
    prev_release = build_release(registry, cosign_key, images, prev_tag)
    curr_release = build_release(registry, cosign_key, images, curr_tag)
    diff         = diff_images(prev_release, curr_release)
    commits      = fetch_commits(prev_tag, curr_tag)
    
    return {
        "prev-tag": prev_tag,
        "curr-tag": curr_tag,
        "images": images,
        "releases": {"previous": prev_release, "current": curr_release},
        "common-packages": common_packages(curr_release),
        "diff": diff,
        "commits": commits,
    }

# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate container image changelogs.")
    
    parser.add_argument("--registry", required=True, help="Container registry (e.g. ghcr.io/ublue-os/)")
    parser.add_argument("--cosign-key", required=True, help="URL or path to cosign public key")
    parser.add_argument("--images", required=True, nargs="+", help="List of image names (e.g. bluefin bluefin-dx)")
    
    parser.add_argument("--prev-tag", help="Previous release tag")
    parser.add_argument("--curr-tag", help="Current release tag")
    parser.add_argument("--stream", help="Release stream for auto-discovery (e.g. stable, latest)")
    
    parser.add_argument("--output", "-o", default="changelog.md", help="Output file path")
    parser.add_argument("--output-env", help="Output environment file path (TITLE=... TAG=...)")
    parser.add_argument("--handwritten", help="Introductory text")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of Markdown")
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    
    return parser.parse_args()

def main():
    # Filter out empty arguments and 'false' which might be passed by GitHub Actions expressions
    sys.argv = [arg for arg in sys.argv if arg and arg != 'false']
    args = parse_args()

    # Flatten images list in case it came in as a single string with spaces
    images = []
    for img in args.images:
        images.extend(img.split())
    args.images = images

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Tag Discovery Logic
    if args.stream:
        if args.prev_tag or args.curr_tag:
            log.warning("Arguments 'prev-tag' and 'curr-tag' ignored due to '--stream'.")
        # Use first image for discovery
        prev_tag, curr_tag = discover_tags(args.registry, args.images[0], args.stream)
        log.info(f"Auto-discovered tags: {prev_tag} -> {curr_tag}")
    else:
        if not args.prev_tag or not args.curr_tag:
            log.error("Must provide either '--stream' OR '--prev-tag' and '--curr-tag'.")
            sys.exit(1)
        prev_tag = args.prev_tag
        curr_tag = args.curr_tag

    data = build_release_data(
        registry=args.registry,
        cosign_key=args.cosign_key,
        images=args.images,
        prev_tag=prev_tag,
        curr_tag=curr_tag
    )

    if args.json:
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
    else:
        md = render_changelog(data, handwritten=args.handwritten)
        with open(args.output, "w") as f:
            f.write(md)
            
    if args.output_env:
        # Generate title similar to old script logic
        variant_label = infer_variant_label(curr_tag)
        title = f"{curr_tag}: {variant_label}"
        with open(args.output_env, "w") as f:
             f.write(f'TITLE="{title}"\nTAG={curr_tag}\n')
        log.info(f"✅ Env file written to {args.output_env}")

    log.info(f"✅ Changelog written to {args.output}")

if __name__ == "__main__":
    main()
