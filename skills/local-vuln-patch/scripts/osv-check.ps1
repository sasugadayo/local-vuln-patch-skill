# Match the packages listed by inventory.ps1 against OSV.dev (https://osv.dev). Windows counterpart of osv-check.sh.
# Sends only ecosystem, package name and version; no paths, user names or host names. Needs no extra tools.
#   powershell -ExecutionPolicy Bypass -File osv-check.ps1 inventory.tsv                  # every known vulnerability
#   powershell -ExecutionPolicy Bypass -File osv-check.ps1 inventory.tsv GHSA-xxxx CVE-…  # only these (IDs or their aliases)
# Output matches osv-check.sh: "## findings", "## locations", "## units".
param([Parameter(Mandatory = $true)][string]$Inventory, [Parameter(ValueFromRemainingArguments = $true)][string[]]$Ids = @())
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12   # Windows PowerShell 5.1 defaults to TLS 1.0
$api = 'https://api.osv.dev/v1'

# Rows of the packages section: ecosystem name version manager path
$pkgs = @(); $in = $false
# No -Encoding: Windows PowerShell 5.1 writes `>` as UTF-16 with a BOM, PowerShell 7 as UTF-8; both are detected
foreach ($l in (Get-Content -LiteralPath $Inventory)) {
  if ($l -like '## *') { $in = $l -like "## packages`t*"; continue }
  $c = $l -split "`t"
  if ($in -and $c.Count -ge 5) { $pkgs += , $c }
}
if (-not $pkgs) { Write-Error "no packages in $Inventory"; exit 1 }
$queries = @($pkgs | ForEach-Object { "$($_[0])`t$($_[1])`t$($_[2])" } | Sort-Object -Unique)

# querybatch takes up to 1000 queries; results come back in the same order
$hits = @()
for ($i = 0; $i -lt $queries.Count; $i += 1000) {
  $chunk = @($queries[$i..([Math]::Min($i + 999, $queries.Count - 1))])
  $body = @{ queries = @($chunk | ForEach-Object { $c = $_ -split "`t"; @{ package = @{ ecosystem = $c[0]; name = $c[1] }; version = $c[2] } }) } |
    ConvertTo-Json -Depth 5 -Compress
  $res = Invoke-RestMethod -Method Post -Uri "$api/querybatch" -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body))
  # ponytail: a package with more than 1000 vulnerabilities gets a next_page_token, which is ignored
  for ($j = 0; $j -lt $chunk.Count; $j++) {
    foreach ($v in @($res.results[$j].vulns)) { if ($v) { $hits += , @(($chunk[$j] -split "`t") + $v.id) } }
  }
}

$vulns = @{}
function Fetch([string]$id) {
  if ($vulns.ContainsKey($id)) { return }
  try { $script:vulns[$id] = Invoke-RestMethod -Uri "$api/vulns/$id" } catch { $script:vulns[$id] = $null }
}

# With IDs given, keep only hits whose ID is one of them or one of their aliases
# (OSV IDs are case-sensitive when fetched, so they are sent as given and compared in upper case)
if ($Ids.Count) {
  $wanted = @{}
  foreach ($id in $Ids) {
    $wanted[$id.ToUpperInvariant()] = 1
    Fetch $id
    if ($vulns[$id]) { foreach ($a in @($vulns[$id].id) + @($vulns[$id].aliases)) { if ($a) { $wanted[$a.ToUpperInvariant()] = 1 } } }
  }
  $hits = @($hits | Where-Object { $wanted.ContainsKey($_[3].ToUpperInvariant()) })
}

function Norm([string]$s) { ($s.ToLowerInvariant() -replace '[-_.]+', '-') }
function Rank([string]$s) { switch ($s.ToUpperInvariant()) { 'CRITICAL' { 4 } 'HIGH' { 3 } 'MODERATE' { 2 } 'MEDIUM' { 2 } 'LOW' { 1 } default { 0 } } }

# The same vulnerability often comes from several databases (GHSA-…, PYSEC-…, GO-…) that list each other
# as aliases. Merge them into one row per package version, keeping every fixed version.
$groups = New-Object System.Collections.ArrayList
$byKey = @{}
foreach ($h in $hits) {
  $e, $n, $ver, $id = $h
  Fetch $id
  $v = $vulns[$id]
  $aliases = @(); $sev = ''; $fixed = @(); $sum = 'details could not be downloaded'
  if ($v) {
    $aliases = @($v.aliases | Where-Object { $_ })
    if ($v.database_specific -and $v.database_specific.severity) { $sev = "$($v.database_specific.severity)" }
    elseif ($v.severity) { $sev = "$(@($v.severity)[0].score)" }
    foreach ($a in @($v.affected)) {
      if ($a.package -and ($a.package.ecosystem -split ':')[0] -eq $e -and (Norm $a.package.name) -eq (Norm $n)) {
        foreach ($r in @($a.ranges)) { foreach ($ev in @($r.events)) { if ($ev.fixed) { $fixed += "$($ev.fixed)" } } }
      }
    }
    $s = if ($v.summary) { $v.summary } else { "$($v.details)" }
    $sum = ($s -replace '[\t\r\n]+', ' ')
    if ($sum.Length -gt 160) { $sum = $sum.Substring(0, 160) }
  }
  $k = "$e`t$n`t$ver"
  $g = $null
  foreach ($x in @($id) + $aliases) { if ($byKey.ContainsKey("$k`t$x")) { $g = $byKey["$k`t$x"]; break } }
  if (-not $g) {
    $g = [pscustomobject]@{ Sev = $sev; Id = $id; Aliases = New-Object System.Collections.ArrayList; Key = $k; Fixed = New-Object System.Collections.ArrayList; Summary = $sum }
    [void]$groups.Add($g)
  } elseif ($g.Sev -match '^CVSS' -and $sev -and $sev -notmatch '^CVSS') { $g.Sev = $sev }
  foreach ($x in @($id) + $aliases) { $byKey["$k`t$x"] = $g; if ($x -ne $g.Id -and -not $g.Aliases.Contains($x)) { [void]$g.Aliases.Add($x) } }
  foreach ($f in $fixed) { if (-not $g.Fixed.Contains($f)) { [void]$g.Fixed.Add($f) } }
}

"## findings`tseverity`tid`taliases`tecosystem`tname`tversion`tfixed`tsummary"
$groups | Sort-Object Key | ForEach-Object { "$($_.Sev)`t$($_.Id)`t$($_.Aliases -join ',')`t$($_.Key)`t$($_.Fixed -join ' ')`t$($_.Summary)" }

""
"## locations`tecosystem`tname`tversion`tmanager`tpath`tids"
$idsOf = @{}; $sevOf = @{}   # not $ids: PowerShell names are case-insensitive and $Ids is the parameter
foreach ($g in $groups) {
  if ($idsOf.ContainsKey($g.Key)) { $idsOf[$g.Key] += ",$($g.Id)" } else { $idsOf[$g.Key] = $g.Id }
  $r = Rank $g.Sev
  if (-not $sevOf.ContainsKey($g.Key) -or $r -gt $sevOf[$g.Key]) { $sevOf[$g.Key] = $r }
}
$locs = @()
foreach ($p in $pkgs) {
  $k = "$($p[0])`t$($p[1])`t$($p[2])"
  if ($idsOf.ContainsKey($k)) { $locs += , ($p[0..4] + $idsOf[$k] + $sevOf[$k]); ($p[0..4] + $idsOf[$k]) -join "`t" }
}

# The thing that is updated as a whole: a pipx / uv tool, a top-level global npm package,
# a Python environment, or a single binary
""
"## units`tmax_severity`tmanager`tunit`tvulnerable_packages`texample_ids"
$units = [ordered]@{}
foreach ($l in $locs) {
  $p = $l[4] -replace '\\', '/'
  $u = $p
  if ($p -match '^(.*/(pipx/venvs|uv/tools)/[^/]+)') { $u = $Matches[1] }
  elseif ($p -match '^(.*?/node_modules/(@[^/]+/)?[^/]+)') { $u = $Matches[1] }
  elseif ($p -match '^(.*?/site-packages)/') { $u = $Matches[1] }
  $k = "$($l[3])`t$u"
  if (-not $units.Contains($k)) { $units[$k] = [pscustomobject]@{ Sev = -1; Pkgs = @{}; Ex = ($l[5] -split ',')[0] } }
  $x = $units[$k]
  $x.Pkgs["$($l[1])`t$($l[2])"] = 1
  if ([int]$l[6] -gt $x.Sev) { $x.Sev = [int]$l[6] }
}
$words = 'unrated', 'LOW', 'MODERATE', 'HIGH', 'CRITICAL'
$units.GetEnumerator() | Sort-Object @{ e = { $_.Value.Sev }; Descending = $true }, @{ e = { $_.Value.Pkgs.Count }; Descending = $true } |
  ForEach-Object { "$($words[$_.Value.Sev])`t$($_.Key)`t$($_.Value.Pkgs.Count)`t$($_.Value.Ex)" }
