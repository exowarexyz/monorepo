#!/usr/bin/env bash
#
# Increment patch versions for crates/packages whose name starts with "exoware-"
# in package declarations and [workspace.dependencies], versions
# in package.json files, and the interface.yaml OpenAPI spec.

set -euo pipefail

# Function: bump the patch number in e.g., 0.0.14 -> 0.0.15
bump_version() {
  local old="$1"
  local major minor patch
  IFS='.' read -r major minor patch <<< "${old}"
  patch=$((patch + 1))
  echo "${major}.${minor}.${patch}"
}

# Recursively find all Cargo.toml files
find . -name "Cargo.toml" | while read -r cargo_file; do
  # We'll store updated file content in an array
  content=()
  changed=false

  # Read the file line by line
  name=""
  while IFS= read -r line; do
    # 1) Match workspace deps like: exoware-foo = { version = "0.0.3", path = "foo" }
    if [[ "${line}" =~ ^[[:space:]]*(exoware-[^[:space:]]+)[[:space:]]*=\ {[[:space:]]*version[[:space:]]*=[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+)\" ]]; then
      old="${BASH_REMATCH[2]}"
      new="$(bump_version "${old}")"
      line="${line/${old}/${new}}"
      changed=true
    fi

    # 2) Check for package name lines like: name = "exoware-foo"
    if [[ "${line}" =~ ^[[:space:]]*name[[:space:]]*=[[:space:]]*\"(exoware-[^\"]+)\" ]]; then
      name="${BASH_REMATCH[1]}"
    else
      # 3) If name is set, we may be on a version line
      if [[ -n "${name}" && "${line}" =~ ^[[:space:]]*version[[:space:]]*=[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+)\" ]]; then
        old="${BASH_REMATCH[1]}"
        new="$(bump_version "${old}")"
        line="${line/${old}/${new}}"
        changed=true
        name=""
      fi
    fi

    content+=("${line}")
  done < "${cargo_file}"

  # If we changed anything, overwrite the file
  if ${changed}; then
    for line in "${content[@]}"; do
      printf "%s\n" "${line}"
    done > "${cargo_file}"
    echo "Updated ${cargo_file}"
  fi
done

# Recursively find all exoware package.json files and update their versions
find . -name "package.json" -print0 | while IFS= read -r -d $'\0' pkg_file; do
  # Check if the package.json is an exoware package
  if grep -q '"name": "exoware-' "$pkg_file"; then
    content=()
    changed=false
    while IFS= read -r line; do
      if [[ "${line}" =~ ^[[:space:]]*\"version\":[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+)\" ]]; then
        old="${BASH_REMATCH[1]}"
        new="$(bump_version "${old}")"
        line="${line/${old}/${new}}"
        changed=true
      fi
      content+=("${line}")
    done < "${pkg_file}"

    if ${changed}; then
      printf "%s\n" "${content[@]}" > "${pkg_file}"
      echo "Updated ${pkg_file}"
    fi
  fi
done

# Update openapi spec
if [ -f "interface.yaml" ]; then
    content=()
    changed=false
    while IFS= read -r line; do
        if [[ "${line}" =~ ^[[:space:]]*version:[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+) ]]; then
            old="${BASH_REMATCH[1]}"
            new="$(bump_version "${old}")"
            line="${line/${old}/${new}}"
            changed=true
        fi
        content+=("${line}")
    done < "interface.yaml"

    if ${changed}; then
        printf "%s\n" "${content[@]}" > "interface.yaml"
        echo "Updated interface.yaml"
    fi
fi