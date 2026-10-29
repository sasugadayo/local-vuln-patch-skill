# local-vuln-patch

An agent skill that checks **your machine** — not your repository — for vulnerable runtimes, global tools and packages, and updates only what you approve.

Dependabot and `npm audit` watch your repositories. Nobody watches the Node, Python and CLI tools installed on the laptop itself, often several versions side by side through different managers. When an advisory lands ("certifi shipped a compromised CA", "Node.js before 22.x has a TLS bug"), this skill answers "am I affected, where, and how do I fix each copy?"

Works on macOS, Linux, and Windows.

## What it finds

- Every install of node, python, go, ruby, php, bun, deno, rust, uv, pip, git, curl, openssl … installed by Homebrew, mise, asdf, nvm / nvm-windows, fnm, volta, n, nodebrew, pyenv / pyenv-win, uv, rbenv, conda, sdkman, rustup, scoop, chocolatey, official installers, or the OS — with which one is active on PATH
- Packages inside them: global npm / pnpm / yarn / bun packages (including nested dependencies), pipx and `uv tool` apps, user-site and virtual-environment Python packages, gems, composer global, dotnet tools, `cargo install` crates
- Bundled copies that are easy to miss: the certifi, urllib3 and requests **vendored inside pip**, packages bundled inside Homebrew formulae, and the libraries and Go standard library **compiled into Go binaries** (`gh`, `trivy`, Docker Desktop's CLIs, …)

Matching uses [OSV.dev](https://osv.dev), for one advisory (GHSA / CVE / PYSEC / GO / RUSTSEC) or for everything known. Results are grouped by what you update as a whole — a Homebrew formula, a pipx app, a global npm package, a Python install — worst first.

## Safety

- The survey only reads. Nothing is changed until you choose it.
- Each copy is updated with the tool that installed it (`brew upgrade --force-bottle`, `mise install`, `pipx runpip`, `uv tool upgrade`, `npm install -g` with that install's own npm, …), with the known traps written down.
- `sudo`, removals and virtual-environment updates are asked about one at a time.
- Files in your repositories (lockfiles, `package.json`, Dockerfiles) are never edited; project dependencies are reported for the repository's own workflow.
- No `curl | sh`, no binaries from advisory links, no `--break-system-packages`.
- Only ecosystem, package name and version are sent to OSV.dev. Paths and user names stay on the machine. The inventory itself makes no network calls.
- After updating, everything is re-checked from a new login shell, because an older install earlier on PATH often keeps winning.

## Install

```bash
npx skills add sasugadayo/local-vuln-patch-skill
```

Then ask your agent, for example:
- "Is this PC affected by GHSA-6q48-6c7w-9gw2? Update if needed."
- "Check my global tools and runtimes for known vulnerabilities."
- "Here is a security notice: <URL>. Check my machine, not the repo."

## Run the survey by hand

macOS / Linux — needs `bash`, `curl` and `jq` (`go` to look inside Go binaries):

```bash
bash skills/local-vuln-patch/scripts/inventory.sh > /tmp/inventory.tsv
bash skills/local-vuln-patch/scripts/osv-check.sh /tmp/inventory.tsv                # everything known
bash skills/local-vuln-patch/scripts/osv-check.sh /tmp/inventory.tsv GHSA-xxxx-...  # one advisory
```

Windows — Windows PowerShell 5.1 or PowerShell 7, nothing else required:

```powershell
powershell -ExecutionPolicy Bypass -File skills\local-vuln-patch\scripts\inventory.ps1 > $env:TEMP\inventory.tsv
powershell -ExecutionPolicy Bypass -File skills\local-vuln-patch\scripts\osv-check.ps1 $env:TEMP\inventory.tsv
```

## Not covered

OS packages (apt, dnf, macOS system files, Windows Update), winget / scoop / chocolatey package versions (compared by hand), GUI and Electron apps, IDE extensions, Docker images, and dependencies inside project repositories. The survey lists these so they are not mistaken for "checked and clean".

## License

MIT
