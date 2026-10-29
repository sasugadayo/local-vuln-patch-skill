#!/usr/bin/env bash
# Read-only inventory for the local-vuln-patch skill. Changes nothing and sends nothing over the network.
# Lists every runtime install and every package installed outside of project repositories,
# with the tool that installed it, so a vulnerability can be matched and updated the right way.
# Output: "## section" headers followed by TSV rows. Runs on macOS (bash 3.2+) and Linux.
#
#   SCAN_ROOTS="$HOME"  space-separated roots searched for Python virtual environments
#   VENV_DEPTH=6        how deep to search for them
set -u

SCAN_ROOTS="${SCAN_ROOTS:-$HOME}"
VENV_DEPTH="${VENV_DEPTH:-6}"
H=$HOME
os=$(uname -s)
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

rp() { realpath "$1" 2>/dev/null || readlink -f "$1" 2>/dev/null || echo "$1"; }
has() { command -v "$1" >/dev/null 2>&1; }

# Order matters: the first matching pattern wins.
manager_of() {
  case "$1" in
    */Cellar/*) echo homebrew ;;
    /Applications/Xcode*) echo system ;;
    /Applications/*) echo "app bundle" ;;
    /usr/local/go/*) echo "go.dev installer" ;;
    */mise/installs/npm-*) echo "mise npm" ;;
    */lib/node_modules/*) echo "npm -g" ;;
    */uv/tools/*) echo "uv tool" ;;
    */uv/python/*) echo "uv python" ;;
    */pipx/venvs/*) echo pipx ;;
    */mise/installs/*) echo mise ;;
    */.asdf/*) echo asdf ;;
    */.nvm/*) echo nvm ;;
    */fnm/*) echo fnm ;;
    */.volta/*) echo volta ;;
    */.nodebrew/*) echo nodebrew ;;
    */n/versions/*) echo n ;;
    */.pyenv/*) echo pyenv ;;
    */.rbenv/*) echo rbenv ;;
    */.goenv/*) echo goenv ;;
    */.sdkman/*) echo sdkman ;;
    */.rustup/*) echo rustup ;;
    */.cargo/*) echo cargo ;;
    */.bun/*) echo bun ;;
    */.deno/*) echo deno ;;
    */pnpm/global/*|*/pnpm-global/*) echo "pnpm global" ;;
    */yarn/global/*) echo "yarn global" ;;
    */miniconda*|*/anaconda*|*/miniforge*|*/mambaforge*|*/conda/*) echo conda ;;
    /opt/homebrew/*|*/linuxbrew/*) echo homebrew ;;
    */go/bin/*) echo "go install" ;;
    "$H"/.local/bin/*) echo ".local/bin (installer script or manual)" ;;
    */composer/*) echo "composer global" ;;
    "$H"/Library/Python/*|"$H"/.local/lib/python*) echo "pip --user" ;;
    /usr/bin/*|/bin/*|/usr/lib/*|/System/*|/Library/Developer/*) echo system ;;
    /usr/local/*) echo "/usr/local (installer)" ;;
    *) echo other ;;
  esac
}

# On macOS, /usr/bin/python3, pip3 and git are shims that open an install dialog when the
# Command Line Tools are missing. Never run them in that case.
runnable() {
  case "$1" in
    /usr/bin/python3|/usr/bin/pip3|/usr/bin/git)
      [ "$os" != Darwin ] || xcode-select -p >/dev/null 2>&1 ;;
    *) return 0 ;;
  esac
}

# A binary that fails to start (missing library, broken install) reports "unknown", not a number
# taken from its error message. Warnings printed before the version line are skipped.
version_of() { # name path
  local out
  case "$1" in
    go) out=$("$2" version 2>&1) ;;
    java) out=$("$2" -version 2>&1) ;;
    openssl) out=$("$2" version 2>&1) ;;
    *) out=$("$2" --version 2>&1) ;;
  esac || return 0
  printf '%s\n' "$out" | grep -viE 'deprecated|warning|error|stack trace|dyld|^PHP|^[[:space:]]' |
    grep -Eo '[0-9]+(\.[0-9]+)+(-[0-9A-Za-z.]+)?' | head -1
}

NAMES="node npm python3 python pip pip3 uv pipx ruby gem go java php composer deno bun rustc cargo dotnet git curl openssl"

echo "## system"
printf "os\t%s\nhome\t%s\n" "$os" "$H"

# ---------------------------------------------------------------- runtimes
{
  for n in $NAMES; do which -a "$n" 2>/dev/null; done
  for d in "$H"/.local/share/mise/installs/*/*/bin "$H"/.asdf/installs/*/*/bin \
           "$H"/.nvm/versions/node/*/bin "$H"/.volta/tools/image/node/*/bin "$H"/.nodebrew/node/*/bin \
           "$H"/.local/share/fnm/node-versions/*/installation/bin \
           "$H/Library/Application Support/fnm/node-versions"/*/installation/bin \
           /usr/local/n/versions/node/*/bin "$H"/n/versions/node/*/bin \
           "$H"/.pyenv/versions/*/bin "$H"/.local/share/uv/python/*/bin "$H"/.rbenv/versions/*/bin \
           "$H"/.goenv/versions/*/bin "$H"/.sdkman/candidates/*/*/bin "$H"/.rustup/toolchains/*/bin \
           /opt/homebrew/Cellar/*/*/bin /usr/local/Cellar/*/*/bin /home/linuxbrew/.linuxbrew/Cellar/*/*/bin \
           "$H"/miniconda3/bin "$H"/anaconda3/bin "$H"/miniforge3/bin "$H"/mambaforge/bin \
           "$H"/.bun/bin "$H"/.deno/bin "$H"/.cargo/bin; do
    for n in $NAMES; do [ -x "$d/$n" ] && [ ! -d "$d/$n" ] && echo "$d/$n"; done
  done
} | while IFS= read -r p; do
  r=$(rp "$p")
  n=$(basename "$p")
  printf '%s\t%s\n' "$r" "$n"
done | sort -u -t "$(printf '\t')" -k1,1 > "$tmp/runtimes.raw"

echo
echo "## runtimes	name	version	manager	active	path"
while IFS="$(printf '\t')" read -r r n; do
  runnable "$r" || { printf '%s\t%s\t%s\t%s\t%s\n' "$n" "skipped (would prompt to install Command Line Tools)" system no "$r"; continue; }
  v=$(version_of "$n" "$r")
  a=no
  cur=$(command -v "$n" 2>/dev/null) && [ "$(rp "$cur")" = "$r" ] && a=yes
  printf '%s\t%s\t%s\t%s\t%s\n' "$n" "${v:-unknown}" "$(manager_of "$r")" "$a" "$r"
done < "$tmp/runtimes.raw" | tee "$tmp/runtimes.tsv"

# ---------------------------------------------------------------- package roots
# Every directory below is walked for installed packages. Project dependencies inside
# repositories (node_modules, lockfiles) are out of scope: they are fixed in the repository.
roots="$tmp/roots"
{
  # Global node_modules of every node install, plus package-manager specific global dirs
  awk -F'\t' '$1=="node"{print $5}' "$tmp/runtimes.tsv" | while IFS= read -r b; do
    echo "$(dirname "$(dirname "$b")")/lib/node_modules"
  done
  has npm && echo "$(npm root -g 2>/dev/null)"
  has pnpm && echo "$(pnpm root -g 2>/dev/null)"
  for d in "$H"/.local/share/mise/installs/npm-* "$H"/.bun/install/global "$H"/.config/yarn/global \
           "$H"/.npm-global "$H"/.local/share/pnpm; do echo "$d"; done
  # Python: interpreter prefixes, user site, pipx, uv tools, conda
  awk -F'\t' '$1=="python3"||$1=="python"{print $5}' "$tmp/runtimes.tsv" | while IFS= read -r b; do
    for s in "$(dirname "$(dirname "$b")")"/lib/python*/site-packages; do echo "$s"; done
  done
  for d in /opt/homebrew/lib/python*/site-packages /usr/local/lib/python*/site-packages \
           "$H"/Library/Python/*/lib/python/site-packages "$H"/.local/lib/python*/site-packages \
           "${PIPX_HOME:-$H/.local/pipx}"/venvs "$H"/.local/share/pipx/venvs \
           "${UV_TOOL_DIR:-$H/.local/share/uv/tools}" \
           "$H"/miniconda3 "$H"/anaconda3 "$H"/miniforge3 "$H"/mambaforge "$H"/opt/miniconda3; do echo "$d"; done
  # Homebrew bundles npm and Python packages inside formulae (libexec)
  for d in /opt/homebrew/Cellar /usr/local/Cellar /home/linuxbrew/.linuxbrew/Cellar; do echo "$d"; done
  # Ruby gems of every ruby install
  awk -F'\t' '$1=="ruby"{print $5}' "$tmp/runtimes.tsv" | while IFS= read -r b; do
    echo "$(dirname "$(dirname "$b")")/lib/ruby/gems"
  done
  for d in "$H"/.gem /opt/homebrew/lib/ruby/gems "$H"/.local/share/gem; do echo "$d"; done
} | while IFS= read -r d; do [ -n "$d" ] && [ -d "$d" ] && rp "$d"; done | sort -u > "$roots"

# Python virtual environments under SCAN_ROOTS (projects, notebooks, ad-hoc venvs)
for r in $SCAN_ROOTS; do
  find "$r" -maxdepth "$VENV_DEPTH" \( -name node_modules -o -name .git -o -name Library -o -name .Trash \
       -o -name pipx -o -name uv -o -name mise -o -name Cellar \) -prune -o -name pyvenv.cfg -print 2>/dev/null
done | while IFS= read -r c; do dirname "$c"; done | sort -u > "$tmp/venvs"

echo
echo "## venvs	in_repo	path"
while IFS= read -r v; do
  top=$(git -C "$v" rev-parse --show-toplevel 2>/dev/null) && in="$top" || in=no
  printf '%s\t%s\n' "$in" "$v"
done < "$tmp/venvs" | tee "$tmp/venvs.tsv"
cat "$tmp/venvs" >> "$roots"

# ---------------------------------------------------------------- packages
# Columns: ecosystem (OSV.dev name), package, version, manager, path of the installed copy
pkg="$tmp/packages"
: > "$pkg"
while IFS= read -r r; do
  find "$r" \( -name .git -prune \) -o \( -name '*.dist-info' -o -name vendor.txt -o -name package.json \
       -o -name '*.gemspec' \) -print 2>/dev/null
done < "$roots" | sort -u > "$tmp/files"

# npm: only <...>/node_modules/<name>/package.json and node_modules/@scope/<name>/package.json
grep -E '/node_modules/(@[^/]+/)?[^/@][^/]*/package\.json$' "$tmp/files" > "$tmp/npm" || true
# One jq per 200 files; a broken package.json only loses its own batch
tr '\n' '\0' < "$tmp/npm" | xargs -0 -n 200 jq -r 'select(.name and .version) | ["npm", .name, .version, input_filename] | @tsv' 2>/dev/null >> "$pkg"

# PyPI: <name>-<version>.dist-info (wheel spec: name has no "-", version has no "-")
grep -E '\.dist-info$' "$tmp/files" | while IFS= read -r f; do
  b=$(basename "$f" .dist-info)
  printf 'PyPI\t%s\t%s\t%s\n' "${b%-*}" "${b##*-}" "$f"
done >> "$pkg"
# Packages vendored inside other packages (pip vendors certifi, urllib3, requests, …)
# (awk, not sed: BSD sed does not turn \t into a tab)
grep -E '/_vendor/vendor\.txt$' "$tmp/files" | while IFS= read -r f; do
  # Sub-dependencies are indented (requests' certifi, idna, urllib3 in older pip)
  awk -v f="$f" '/^[[:space:]]*[A-Za-z0-9._-]+==/ { sub(/^[[:space:]]+/, ""); split($0, a, "=="); split(a[2], b, /[ ;#]/); print "PyPI\t" a[1] "\t" b[1] "\t" f }' "$f"
done >> "$pkg"

# RubyGems: specifications/<name>-<version>[-<platform>].gemspec
grep -E '/specifications/[^/]+\.gemspec$' "$tmp/files" | awk '{
  b = $0; sub(/^.*\//, "", b); sub(/\.gemspec$/, "", b)
  n = split(b, p, "-")
  for (i = 2; i <= n; i++) if (p[i] ~ /^[0-9]/) {          # first dash-segment that starts with a digit
    name = p[1]; for (j = 2; j < i; j++) name = name "-" p[j]
    print "RubyGems\t" name "\t" p[i] "\t" $0; break
  }
}' >> "$pkg"

# Go: module versions compiled into binaries (`go version -m`), plus the toolchains themselves as stdlib
if has go; then
  for d in "$(go env GOBIN 2>/dev/null)" "$(go env GOPATH 2>/dev/null)/bin" "$H/go/bin" "$H/.local/bin" \
           /opt/homebrew/bin /usr/local/bin "$H"/.local/share/mise/installs/*/*/bin; do
    [ -n "$d" ] && [ -d "$d" ] && for f in "$d"/*; do [ -f "$f" ] && [ -x "$f" ] && rp "$f"; done
  done | sort -u | tr '\n' '\0' | xargs -0 go version -m 2>/dev/null | awk -F'\t' '
    /^[^\t].*: go[0-9]/ { file=$0; sub(/: go[0-9].*$/, "", file); v=$0; sub(/^.*: go/, "", v); print "Go\tstdlib\t" v "\t" file; next }
    $2=="mod" || $2=="dep" { if ($4 != "(devel)") print "Go\t" $3 "\t" $4 "\t" file }
  ' >> "$pkg"
fi
awk -F'\t' '$1=="go" && $2 ~ /^[0-9]/ {print "Go\tstdlib\t" $2 "\t" $5}' "$tmp/runtimes.tsv" >> "$pkg"

# crates.io: binaries installed with cargo install (only the top-level crate is recorded)
[ -f "$H/.cargo/.crates2.json" ] && jq -r --arg f "$H/.cargo/.crates2.json" \
  '.installs | keys[] | split(" ") | ["crates.io", .[0], .[1], $f] | @tsv' "$H/.cargo/.crates2.json" 2>/dev/null >> "$pkg"

# Packagist: composer global
for f in "$H"/.composer/vendor/composer/installed.json "$H"/.config/composer/vendor/composer/installed.json; do
  [ -f "$f" ] && jq -r --arg f "$f" '(.packages // .)[] | ["Packagist", .name, (.version | ltrimstr("v")), $f] | @tsv' "$f" 2>/dev/null >> "$pkg"
done

# NuGet: dotnet global tools
has dotnet && dotnet tool list -g 2>/dev/null | awk 'NR>2 && NF>=2 {print "NuGet\t" $1 "\t" $2 "\tdotnet tool -g"}' >> "$pkg"

echo
echo "## packages	ecosystem	name	version	manager	path"
sort -u "$pkg" | while IFS="$(printf '\t')" read -r e n v p; do
  [ -n "$e" ] && [ -n "$v" ] || continue
  m=$(manager_of "$p")
  case "$p" in "dotnet tool -g") m="dotnet tool" ;; esac
  # venvs found under SCAN_ROOTS
  if [ "$m" = other ] || [ "$m" = "/usr/local (installer)" ]; then
    while IFS="$(printf '\t')" read -r in v2; do
      case "$p" in "$v2"/*) [ "$in" = no ] && m=venv || m="venv in repo $in"; break ;; esac
    done < "$tmp/venvs.tsv"
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$e" "$n" "$v" "$m" "$p"
done

# ---------------------------------------------------------------- homebrew
if has brew; then
  echo
  echo "## homebrew	formula	versions"
  brew list --formula --versions 2>/dev/null | awk '{f=$1; $1=""; sub(/^ /,""); print f "\t" $0}'
fi

echo
echo "## not_checked	what	where to look instead"
has jq || printf '%s\t%s\n' "npm, cargo and composer packages (jq is not installed)" "install jq and run again"
has go || printf '%s\t%s\n' "libraries compiled into Go binaries (go is not installed)" "install go and run again"
cat <<'EOF'
OS packages (apt, dnf, pacman, macOS system software)	the OS updater
GUI apps, Electron apps, browsers and their bundled runtimes	each app's own updater
IDE / editor extensions	the editor's extension manager
Docker images and containers	rebuild or pull the image
Dependencies inside project repositories (node_modules, lockfiles)	fix in each repository
conda packages that are not Python packages (openssl, libcurl, …)	conda list -n <env>
Python packages installed as .egg-info	pip list in that environment
Go binaries built with replace directives	the replaced module is not checked
Rust crates installed with cargo install (dependencies)	cargo audit bin <binary> if cargo-audit is installed
EOF
