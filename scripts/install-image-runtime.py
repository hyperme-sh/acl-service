"""Install the frozen runtime with repository-scoped, ephemeral Git headers."""
import base64
import os
from pathlib import Path
import subprocess
import tomllib
from urllib.parse import urlsplit

lock = tomllib.loads(Path("uv.lock").read_text())
repositories = set()
for package in lock["package"]:
    source = package.get("source", {}).get("git")
    if not source:
        continue
    url = urlsplit(source)
    if (url.scheme != "https" or url.hostname != "github.com"
            or url.username or url.password or url.port
            or not url.path.startswith("/hyperme-sh/")
            or len(url.path.strip("/").split("/")) != 2):
        raise SystemExit("Unexpected private dependency repository")
    repositories.add(f"https://github.com{url.path}")
token = Path("/run/secrets/dependency_read_token").read_text().strip()
if not token:
    raise SystemExit("A dependency read token is required")
header = base64.b64encode(f"x-access-token:{token}".encode()).decode()
env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_CONFIG_")}
env["GIT_CONFIG_COUNT"] = str(len(repositories))
for index, repository in enumerate(sorted(repositories)):
    env[f"GIT_CONFIG_KEY_{index}"] = f"http.{repository}.extraheader"
    env[f"GIT_CONFIG_VALUE_{index}"] = f"AUTHORIZATION: basic {header}"
subprocess.run(["uv", "sync", "--frozen", "--no-dev", "--no-editable", "--no-cache"], env=env, check=True)
