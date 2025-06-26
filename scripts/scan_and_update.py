import os
import sys
import requests
import vt
import hashlib
from pathlib import Path
from github import Github

# Download release assets, compute SHA‑256, reuse existing VT report when present,
# otherwise upload (wait_for_completion=True), then link VT GUI URL in README.

API_HEADERS = {"Accept": "application/vnd.github.v3+json"}

def get_two_tags(repo_name: str, gh_token: str):
    """Return (prerelease_tag, stable_tag). Either may be None."""
    releases_url = f"https://api.github.com/repos/{repo_name}/releases?per_page=100"
    r = requests.get(releases_url,
                     headers={**API_HEADERS, "Authorization": f"token {gh_token}"},
                     timeout=30)
    r.raise_for_status()
    releases = r.json()

    prerelease = next((rel for rel in releases if rel.get("prerelease")), None)
    stable = next((rel for rel in releases if not rel.get("prerelease")), None)

    prerelease_tag = prerelease.get("tag_name") if prerelease else None
    stable_tag = stable.get("tag_name") if stable else None

    return prerelease_tag, stable_tag

def get_release_for_tag(repo_name: str, tag: str, gh_token: str):
    url = f"https://api.github.com/repos/{repo_name}/releases/tags/{tag}"
    r = requests.get(url,
                     headers={**API_HEADERS, "Authorization": f"token {gh_token}"},
                     timeout=30)
    if r.status_code == 404:
        print(f"No GitHub *release* found for tag {tag}; skipping.")
        return None
    r.raise_for_status()
    return r.json()

def sha256_and_save(url: str, save_path: Path) -> str:
    sha = hashlib.sha256()
    with requests.get(url, stream=True, timeout=60) as resp:
        resp.raise_for_status()
        save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(save_path, "wb") as f:
            for chunk in resp.iter_content(8192):
                f.write(chunk)
                sha.update(chunk)
    return sha.hexdigest()


def vt_score_str(stats: dict) -> str:
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)
    return f"{malicious}/{total}"

def main():
    # Common env variables
    # --------------------

    # VirusTotal API key. 500 requests per day, 15.5K requests per month.
    vt_key = os.getenv("VT_API_KEY")

    # Github token. Automatically set in Github Action.
    gh_token = os.getenv("GITHUB_TOKEN")

    # Repository to scan. Should be in format "simplex-chat/simplex-chat".
    scan_repo = os.getenv("REPOSITORY_TO_SCAN")

    # Repository to commit changes.
    update_repo = os.getenv("GITHUB_REPOSITORY")

    # Exclude patterns and names. Can be comma seperated.
    exclude_names = {n.strip() for n in os.getenv("EXCLUDE_NAMES", "").split(',') if n.strip()}
    prefixes = [p for p in os.getenv("EXCLUDE_PREFIXES", "").split(',') if p]

    # Check if variables exist early. If not - bail out.
    if not vt_key or not gh_token or not scan_repo or not update_repo:
        print("ERROR: Missing VT_API_KEY, GITHUB_TOKEN, or REPOSITORY_TO_SCAN")
        sys.exit(1)

    # Clients setup
    # -------------

    vt_client = vt.Client(vt_key)
    gh = Github(gh_token)
    gh_repo = gh.get_repo(update_repo)

    beta_tag, stable_tag = get_two_tags(scan_repo, gh_token)
    tags_to_scan = [t for t in (beta_tag, stable_tag) if t]

    if not tags_to_scan:
        print("No suitable tags found.")
        return

    # Init tuple for final table.
    # Format: markdown_linl, mal, sys, und
    results = []

    for tag in tags_to_scan:
        rel = get_release_for_tag(scan_repo, tag, gh_token)
        if not rel:
            continue

        tag_results = []
        for asset in rel.get("assets", []):
            name = asset.get("name")
            if (not name or name in exclude_names
                    or any(name.startswith(p) for p in prefixes)):
                continue

            url = asset.get("browser_download_url")
            if not url:
                continue

            save_path = Path("assets") / tag / name
            print(f"Downloading {name} ({tag}) …")

            try:
                sha256 = sha256_and_save(url, save_path)
            except Exception as e:
                print(f"Download error for {name}: {e}")
                continue

            markdown_link = f"[{name}](https://www.virustotal.com/gui/file/{sha256})"

            try:
                file_obj = vt_client.get_object(f"/files/{sha256}")
                stats = file_obj.last_analysis_stats
                print(f"Cache hit for {name}")
            except vt.error.APIError as e:
                # Explicitly check 404 for NotFound
                if getattr(e, "code", None) == "NotFoundError":
                    print(f"Not found in VT cache, uploading {name} ...")
                    try:
                        with open(save_path, "rb") as f:
                            analysis = vt_client.scan_file(f, wait_for_completion=True)
                        stats = analysis.last_analysis_stats
                    except Exception as up_err:
                        print(f"Upload failed for {name}: {up_err}")
                        continue
                else:
                    print(f"VT error for {name}: {e}")
                    continue

            tag_results.append((markdown_link, vt_score_str(stats)))


        if tag_results:
            results.append((tag, tag_results))

    vt_client.close()


    if not results:
        print("Nothing scanned.")
        return

    # Let's build README
    lines = ["# VirusTotal Scan Results", ""]
    for tag, files in results:
        lines.append(f"## {tag}")
        lines.append("| File | Threat level |")
        lines.append("| ---- | ------------ |")
        for link, score in files:
            lines.append(f"| {link} | {score} |")
        lines.append("")  # blank line between tables
    content = "\n".join(lines)

    # And commit everything to our READM
    try:
        readme = gh_repo.get_contents("README.md")
        gh_repo.update_file(
            readme.path,
            "chore: update README with VT scan results",
            content,
            readme.sha,
        )
        print("README.md successfully updated.")
    except Exception as e:
        print(f"Failed to update README.md: {e}")

if __name__ == "__main__":
    main()
