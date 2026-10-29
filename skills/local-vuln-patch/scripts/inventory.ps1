# Read-only inventory for the local-vuln-patch skill (Windows). Changes nothing and sends nothing over the network.
# Output matches inventory.sh: "## section" headers followed by TSV rows. Works in Windows PowerShell 5.1 and PowerShell 7.
#   powershell -ExecutionPolicy Bypass -File inventory.ps1 [-ScanRoots C:\src,D:\work] [-VenvDepth 6]
param([string[]]$ScanRoots = @($HOME), [int]$VenvDepth = 6)
$ErrorActionPreference = 'SilentlyContinue'
$ad = $env:APPDATA; $la = $env:LOCALAPPDATA; $pf = $env:ProgramFiles

# Order matters: the first matching pattern wins. Paths are compared with forward slashes.
function Manager([string]$p) {
  $q = $p -replace '\\', '/'
  $rules = @(
    @('/mise/installs/npm-', 'mise npm'), @('/node_modules/', 'npm -g'),
    @('/uv/tools/', 'uv tool'), @('/uv/python/', 'uv python'), @('/pipx/venvs/', 'pipx'),
    @('/mise/installs/', 'mise'), @('/nvm/', 'nvm-windows'), @('/fnm/', 'fnm'), @('/Volta/', 'volta'),
    @('/scoop/', 'scoop'), @('/chocolatey/', 'chocolatey'), @('/pyenv', 'pyenv'),
    @('/miniconda|/anaconda|/miniforge|/mambaforge', 'conda'),
    @('/WindowsApps/', 'Microsoft Store'), @('/Roaming/Python/', 'pip --user'),
    @('/Programs/Python/', 'python.org installer'), @('/go/bin/', 'go install'),
    @('/.cargo/', 'cargo'), @('/.rustup/', 'rustup'), @('/.bun/', 'bun'), @('/.deno/', 'deno'),
    @('/Composer/', 'composer global'), @('/Windows/', 'system'), @('/Program Files', 'installer')
  )
  foreach ($r in $rules) { if ($q -match $r[0]) { return $r[1] } }
  'other'
}

function Real([string]$p) {
  $i = Get-Item -LiteralPath $p -Force
  if ($i -and $i.LinkType -and $i.Target) {
    $t = @($i.Target)[0]
    if (-not [IO.Path]::IsPathRooted($t)) { $t = Join-Path (Split-Path $p) $t }
    return [IO.Path]::GetFullPath($t)
  }
  $p
}

# Directory walker that skips links/junctions (no loops) and the named directories
function Walk([string]$root, [int]$depth, [string[]]$prune, [scriptblock]$want) {
  $stack = New-Object System.Collections.Stack
  $stack.Push(@($root, 0))
  while ($stack.Count) {
    $e = $stack.Pop()
    foreach ($c in (Get-ChildItem -LiteralPath $e[0] -Force)) {
      if (& $want $c) { $c.FullName }
      if ($c.PSIsContainer -and -not ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
          $prune -notcontains $c.Name -and $e[1] -lt $depth) { $stack.Push(@($c.FullName, ($e[1] + 1))) }
    }
  }
}

function VersionOf([string]$name, [string]$path) {
  switch ($name) {
    'go' { $out = & $path version 2>&1 }
    'java' { $out = & $path -version 2>&1 }
    'openssl' { $out = & $path version 2>&1 }
    default { $out = & $path --version 2>&1 }
  }
  if ($LASTEXITCODE -ne 0) { return 'unknown' }
  foreach ($l in @($out)) {
    $s = "$l"
    if ($s -match '(?i)deprecated|warning|error|stack trace|^PHP|^\s') { continue }
    if ($s -match '\d+(\.\d+)+(-[0-9A-Za-z.]+)?') { return $Matches[0] }
  }
  'unknown'
}

$names = 'node', 'npm', 'python', 'python3', 'pip', 'pip3', 'uv', 'pipx', 'ruby', 'gem', 'go', 'java', 'php',
         'composer', 'deno', 'bun', 'rustc', 'cargo', 'dotnet', 'git', 'curl', 'openssl'

"## system"
"os`tWindows"
"home`t$HOME"

# ---------------------------------------------------------------- runtimes
$dirs = @()
foreach ($g in @("$ad\nvm\v*", "$env:NVM_HOME\v*", "$ad\fnm\node-versions\*\installation", "$la\fnm\node-versions\*\installation",
                 "$la\Volta\tools\image\node\*", "$HOME\scoop\apps\*\*", "$la\Programs\Python\Python*",
                 "$HOME\.pyenv\pyenv-win\versions\*", "$ad\uv\python\*", "$la\mise\installs\*\*",
                 "$pf\nodejs", "$pf\Go", "$HOME\miniconda3", "$HOME\anaconda3", "$HOME\miniforge3",
                 "$HOME\.cargo", "$HOME\.bun", "$HOME\.deno")) {
  if ($g -notmatch '^\\') { $dirs += @(Get-Item -Path $g -Force | Where-Object { $_.PSIsContainer -and $_.Name -ne 'current' }) }
}
$cands = @()
foreach ($n in $names) { $cands += @(Get-Command -All -CommandType Application $n | ForEach-Object { $_.Source }) }
foreach ($d in $dirs) {
  foreach ($sub in @('', 'bin', 'Scripts')) {
    foreach ($n in $names) {
      foreach ($ext in @('.exe', '.cmd', '')) {
        $p = Join-Path (Join-Path $d.FullName $sub) "$n$ext"
        if (Test-Path -LiteralPath $p -PathType Leaf) { $cands += $p }
      }
    }
  }
}
$seen = @{}
$runtimes = @()
foreach ($p in $cands) {
  $r = Real $p
  $k = $r.ToLowerInvariant()
  if ($seen.ContainsKey($k)) { continue }
  $seen[$k] = 1
  $n = [IO.Path]::GetFileNameWithoutExtension($r)
  if ($names -notcontains $n) { $n = [IO.Path]::GetFileNameWithoutExtension($p) }
  $active = 'no'
  $cur = Get-Command -CommandType Application $n | Select-Object -First 1
  if ($cur -and (Real $cur.Source).ToLowerInvariant() -eq $k) { $active = 'yes' }
  # The Microsoft Store python aliases open the Store when Python is not installed. Never run them.
  if ($r -match 'WindowsApps' -and $n -match '^python') { $v = 'skipped (Microsoft Store alias)' } else { $v = VersionOf $n $r }
  $runtimes += [pscustomobject]@{ Name = $n; Version = $v; Manager = (Manager $r); Active = $active; Path = $r }
}
""
"## runtimes`tname`tversion`tmanager`tactive`tpath"
$runtimes | ForEach-Object { "$($_.Name)`t$($_.Version)`t$($_.Manager)`t$($_.Active)`t$($_.Path)" }

# ---------------------------------------------------------------- package roots
# Project dependencies inside repositories are out of scope: they are fixed in the repository.
$roots = @()
foreach ($rt in $runtimes) {
  $bin = Split-Path $rt.Path
  $prefix = Split-Path $bin
  if ($rt.Name -eq 'node') { $roots += "$bin\node_modules", (Join-Path $prefix 'lib/node_modules') }
  if ($rt.Name -match '^python') { $roots += "$bin\Lib\site-packages", "$prefix\Lib\site-packages"; $roots += @(Get-Item -Path (Join-Path $prefix 'lib/python*/site-packages') | ForEach-Object { $_.FullName }) }
  if ($rt.Name -eq 'ruby') { $roots += Join-Path $prefix 'lib/ruby/gems' }
}
if (Get-Command npm) { $roots += (npm root -g 2>$null) }
if (Get-Command pnpm) { $roots += (pnpm root -g 2>$null) }
$roots += "$ad\npm\node_modules", "$la\Yarn\Data\global\node_modules", "$HOME\.bun\install\global\node_modules",
          "$ad\Python", "$HOME\pipx\venvs", "$la\pipx\pipx\venvs", "$env:PIPX_HOME\venvs", "$ad\uv\tools",
          "$HOME\miniconda3", "$HOME\anaconda3", "$HOME\miniforge3", "$HOME\.gem"
$roots += @(Get-Item -Path "$la\mise\installs\npm-*" | ForEach-Object { $_.FullName })

# Python virtual environments under ScanRoots
$venvs = @()
foreach ($r in $ScanRoots) {
  $venvs += @(Walk $r $VenvDepth @('node_modules', '.git', 'AppData', 'pipx', 'uv', 'mise', 'scoop') { param($c) $c.Name -eq 'pyvenv.cfg' } |
    ForEach-Object { Split-Path $_ })
}
""
"## venvs`tin_repo`tpath"
$venvRows = @()
foreach ($v in ($venvs | Sort-Object -Unique)) {
  $top = git -C $v rev-parse --show-toplevel 2>$null
  if (-not $top) { $top = 'no' }
  $venvRows += , @($top, $v)
  "$top`t$v"
}
$roots += $venvs

# ---------------------------------------------------------------- packages
$pkgs = @()
function Add-Pkg($e, $n, $v, $p) { if ($e -and $n -and $v) { $script:pkgs += , @($e, $n, $v, $p) } }

$rootSeen = @{}
foreach ($r in $roots) {
  if (-not $r -or -not (Test-Path -LiteralPath $r -PathType Container)) { continue }
  $k = (Real $r).ToLowerInvariant()
  if ($rootSeen.ContainsKey($k)) { continue }
  $rootSeen[$k] = 1
  $files = Walk $r 64 @('.git') { param($c) $c.Name -like '*.dist-info' -or $c.Name -in 'vendor.txt', 'package.json' -or $c.Name -like '*.gemspec' }
  foreach ($f in $files) {
    $u = $f -replace '\\', '/'
    if ($u -match '/node_modules/(@[^/]+/)?[^/@][^/]*/package\.json$') {
      try { $j = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json; Add-Pkg 'npm' $j.name $j.version $f } catch { }
    } elseif ($u -match '([^/]+)-([^-/]+)\.dist-info$') {
      Add-Pkg 'PyPI' $Matches[1] $Matches[2] $f
    } elseif ($u -match '/_vendor/vendor\.txt$') {
      # Sub-dependencies are indented (requests' certifi, idna, urllib3 in older pip)
      foreach ($l in (Get-Content -LiteralPath $f)) { if ($l -match '^\s*([A-Za-z0-9._-]+)==([^\s;#]+)') { Add-Pkg 'PyPI' $Matches[1] $Matches[2] $f } }
    } elseif ($u -match '/specifications/([^/]+)\.gemspec$') {
      $parts = $Matches[1] -split '-'
      for ($i = 1; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -match '^\d') { Add-Pkg 'RubyGems' ($parts[0..($i - 1)] -join '-') $parts[$i] $f; break }
      }
    }
  }
}

# Go: module versions compiled into binaries, plus the toolchains themselves as stdlib
if (Get-Command go) {
  $bins = @()
  foreach ($d in @((go env GOBIN), (Join-Path (go env GOPATH) 'bin'), "$HOME\go\bin", "$HOME\.local\bin")) {
    if ($d -and (Test-Path -LiteralPath $d)) { $bins += @(Get-ChildItem -LiteralPath $d -File | ForEach-Object { $_.FullName }) }
  }
  if ($bins) {
    $file = $null
    foreach ($l in (go version -m @($bins | Sort-Object -Unique) 2>$null)) {
      $c = "$l" -split "`t"
      if ("$l" -match '^(\S.*): go(\d\S*)') { $file = $Matches[1]; Add-Pkg 'Go' 'stdlib' $Matches[2] $file }
      elseif ($c.Count -ge 4 -and ($c[1] -eq 'mod' -or $c[1] -eq 'dep') -and $c[3] -ne '(devel)') { Add-Pkg 'Go' $c[2] $c[3] $file }
    }
  }
}
foreach ($rt in $runtimes) { if ($rt.Name -eq 'go' -and $rt.Version -match '^\d') { Add-Pkg 'Go' 'stdlib' $rt.Version $rt.Path } }

# crates.io: binaries installed with cargo install (only the top-level crate is recorded)
$cr = "$HOME\.cargo\.crates2.json"
if (Test-Path -LiteralPath $cr) {
  try { (Get-Content -LiteralPath $cr -Raw | ConvertFrom-Json).installs.PSObject.Properties | ForEach-Object { $s = $_.Name -split ' '; Add-Pkg 'crates.io' $s[0] $s[1] $cr } } catch { }
}
# Packagist: composer global
$ci = "$ad\Composer\vendor\composer\installed.json"
if (Test-Path -LiteralPath $ci) {
  try {
    $j = Get-Content -LiteralPath $ci -Raw | ConvertFrom-Json
    $list = if ($j.packages) { $j.packages } else { $j }
    foreach ($x in $list) { Add-Pkg 'Packagist' $x.name ($x.version -replace '^v', '') $ci }
  } catch { }
}
# NuGet: dotnet global tools
if (Get-Command dotnet) {
  dotnet tool list -g 2>$null | Select-Object -Skip 2 | ForEach-Object { $c = -split $_; if ($c.Count -ge 2) { Add-Pkg 'NuGet' $c[0] $c[1] 'dotnet tool -g' } }
}

""
"## packages`tecosystem`tname`tversion`tmanager`tpath"
$out = @{}
foreach ($x in $pkgs) {
  $m = Manager $x[3]
  if ($x[3] -eq 'dotnet tool -g') { $m = 'dotnet tool' }
  if ($m -eq 'other' -or $m -eq 'installer') {
    foreach ($v in $venvRows) {
      if ($x[3].StartsWith($v[1] + [IO.Path]::DirectorySeparatorChar)) { if ($v[0] -eq 'no') { $m = 'venv' } else { $m = "venv in repo $($v[0])" }; break }
    }
  }
  $out["$($x[0])`t$($x[1])`t$($x[2])`t$m`t$($x[3])"] = 1
}
$out.Keys | Sort-Object

""
"## not_checked`twhat`twhere to look instead"
if (-not (Get-Command go)) { "libraries compiled into Go binaries (go is not installed)`tinstall go and run again" }
@(
  "winget, scoop and chocolatey packages themselves`twinget upgrade / scoop status / choco outdated",
  "Windows and Microsoft Store apps`tWindows Update / Microsoft Store",
  "GUI apps, Electron apps, browsers and their bundled runtimes`teach app's own updater",
  "IDE / editor extensions`tthe editor's extension manager",
  "Docker images and containers`trebuild or pull the image",
  "Dependencies inside project repositories (node_modules, lockfiles)`tfix in each repository",
  "conda packages that are not Python packages (openssl, libcurl, ...)`tconda list -n <env>",
  "Python packages installed as .egg-info`tpip list in that environment",
  "Go binaries built with replace directives`tthe replaced module is not checked",
  "Rust crates installed with cargo install (dependencies)`tcargo audit bin <binary> if cargo-audit is installed"
)
