# /// script
# dependencies = [
#   "pyaml"
# ]
# ///
import pyaml
import sys
import os
from typing import Any
from image_version import version

def pipeline(tag: str, should_publish: bool=False) -> dict[str, Any]:
    repo = "packages.buildkite.com/nresare/idelephant/idelephant"
    step = {
                "label": ":whale: build docker image",

                "commands": [
                    "cargo fmt --check",
                    "cargo clippy --workspace --locked",
                    "cargo test --workspace --locked",
                    f"docker buildx build -t {repo}:{tag} ."
                ],
            }
    if should_publish:
        step["plugins"] = [
            {"docker-image-push#v1.1.0": {"provider": "buildkite", "image": "idelephant", "tag": tag,"buildkite": {"auth-method": "oidc"}}},
        ]
    return {"steps": [step]}


def main():

    p = pipeline(f"v{version()}", os.getenv("BUILDKITE_BRANCH") == "main")
    pyaml.dump(p, sys.stdout)


if __name__ == "__main__":
    main()
