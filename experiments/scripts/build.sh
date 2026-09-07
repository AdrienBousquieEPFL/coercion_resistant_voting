#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$project_dir"
go_bin="${GO_BIN:-go}"
# Require preinstalled tools and cached modules; never download dependencies.
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
version="$("$go_bin" version)"
if [[ "$version" != "go version go1.26.1 "* ]]; then
  echo "Go 1.26.1 is required. Set GO_BIN to its executable. Found: $version" >&2
  exit 1
fi
mkdir -p bin
"$go_bin" build -trimpath -o bin/voting-experiments .
echo "Built $project_dir/bin/voting-experiments"
