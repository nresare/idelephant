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


def pipeline(tag: str, should_publish: bool = False) -> dict[str, Any]:
    rust_test = {
        "label": ":rust: rust build and test",
        "commands": [
            "cargo fmt --check",
            "cargo clippy --workspace --locked",
            "cargo test --workspace --locked",
        ],
    }
    docker: dict[str, Any] = {
        "label": ":whale: build docker image",
        "command": f"docker buildx build -t idelephant:{tag} .",
        "agents": {"arch": "arm64"},
    }
    if should_publish:
        docker["depends_on"] = "rust_test"
        docker["plugins"] = [
            {
                "docker-image-push#v1.1.0": {
                    "provider": "buildkite",
                    "image": "idelephant",
                    "tag": tag,
                    "buildkite": {"auth-method": "oidc"},
                }
            },
        ]
    return {"steps": [rust_test, docker]}


def main():

    p = pipeline(f"v{version()}", os.getenv("BUILDKITE_BRANCH") == "main")
    pyaml.dump(p, sys.stdout)


if __name__ == "__main__":
    main()
