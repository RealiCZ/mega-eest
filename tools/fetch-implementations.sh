#!/usr/bin/env bash
# Checks the evm2-based implementation and its evm2 fork out at their pins
# (adapters/implementations.env) into vendor/, laid out so that the relative path its crates use
# for evm2 (../../evm2 from mega-evm/next) resolves:
#
#   vendor/mega-evm   EVM2_IMPL_REPO at EVM2_IMPL_REV
#   vendor/evm2       EVM2_FORK_REPO at EVM2_FORK_REV
#
# vendor/ is git-ignored. A checkout already at its pin is kept; anything else there is replaced.
# The revm-based implementation needs no checkout: cargo fetches it as a git dependency.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../adapters/implementations.env
source "$root/adapters/implementations.env"
vendor="$root/vendor"
mkdir -p "$vendor"

fetch() { # <dir> <repo> <rev>
  local dir=$1 repo=$2 rev=$3
  if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$rev" ] \
      && [ -z "$(git -C "$dir" status --porcelain)" ]; then
    echo "fetch-implementations: $(basename "$dir") at $rev"
    return
  fi
  rm -rf "$dir"
  git init -q "$dir"
  git -C "$dir" remote add origin "$repo"
  # One retry: the fetch is by commit, so a retry cannot pick up anything else.
  git -C "$dir" fetch -q --depth 1 origin "$rev" || git -C "$dir" fetch -q --depth 1 origin "$rev"
  git -C "$dir" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
  test "$(git -C "$dir" rev-parse HEAD)" = "$rev"
  echo "fetch-implementations: $(basename "$dir") checked out at $rev"
}

fetch "$vendor/mega-evm" "$EVM2_IMPL_REPO" "$EVM2_IMPL_REV"
# The implementation pins its own fork; the two pins must agree.
pinned=$(sed -n 's/^EVM2_FORK_REV=//p' "$vendor/mega-evm/next/evm2-fork.env")
if [ "$pinned" != "$EVM2_FORK_REV" ]; then
  echo "fetch-implementations: next/evm2-fork.env pins $pinned, adapters/implementations.env $EVM2_FORK_REV" >&2
  exit 1
fi
fetch "$vendor/evm2" "$EVM2_FORK_REPO" "$EVM2_FORK_REV"
