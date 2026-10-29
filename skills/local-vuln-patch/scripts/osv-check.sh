#!/usr/bin/env bash
# Match the packages listed by inventory.sh against OSV.dev (https://osv.dev).
# Sends only ecosystem, package name and version; no paths, user names or host names.
# Needs curl and jq.
#
#   bash scripts/osv-check.sh inventory.tsv                 # every known vulnerability
#   bash scripts/osv-check.sh inventory.tsv GHSA-xxxx CVE-… # only these (IDs or their aliases)
#
# Output: "## findings"  one row per vulnerable package version
#         "## locations" every installed copy of a vulnerable version
#         "## units"     those copies grouped by what gets updated as a whole, worst first
set -eu

[ $# -ge 1 ] || { echo "usage: $0 inventory.tsv [VULN_ID...]" >&2; exit 2; }
for c in curl jq; do command -v "$c" >/dev/null 2>&1 || { echo "$c is required" >&2; exit 2; }; done
inv=$1; shift
api=https://api.osv.dev/v1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Rows of the packages section: ecosystem name version manager path
awk -F'\t' '/^## /{p=($1=="## packages"); next} p && NF>=5' "$inv" > "$tmp/pkgs"
cut -f1-3 "$tmp/pkgs" | sort -u > "$tmp/queries"
[ -s "$tmp/queries" ] || { echo "no packages in $inv" >&2; exit 1; }

# querybatch takes up to 1000 queries; results come back in the same order
split -l 1000 "$tmp/queries" "$tmp/chunk."
for c in "$tmp"/chunk.*; do
  jq -R -s 'split("\n") | map(select(length>0) | split("\t") | {package:{ecosystem:.[0], name:.[1]}, version:.[2]}) | {queries:.}' "$c" |
    curl -sSf --retry 3 -H 'Content-Type: application/json' -d @- "$api/querybatch" > "$c.json"
  # ponytail: a package with more than 1000 vulnerabilities gets a next_page_token, which is ignored
  jq -r --rawfile q "$c" '($q | split("\n") | map(select(length>0))) as $l
    | .results | to_entries[] | .key as $i | (.value.vulns // [])[] | "\($l[$i])\t\(.id)"' "$c.json"
done > "$tmp/hits"

mkdir "$tmp/v"
fetch() { xargs -P 8 -I{} curl -sSf --retry 3 -o "$tmp/v/{}.json" "$api/vulns/{}"; }

# With IDs given, keep only hits whose ID is one of them or one of their aliases,
# so only those records are downloaded
# (OSV IDs are case-sensitive when fetched, so they are sent as given and compared in upper case)
if [ $# -gt 0 ]; then
  printf '%s\n' "$@" | fetch || true
  { printf '%s\n' "$@"; cat "$tmp"/v/*.json 2>/dev/null | jq -r '.id, (.aliases // [])[]'; } |
    tr '[:lower:]' '[:upper:]' | sort -u > "$tmp/wanted"
  awk -F'\t' 'NR==FNR {w[$1]; next} toupper($4) in w' "$tmp/wanted" "$tmp/hits" > "$tmp/hits.f"
  mv "$tmp/hits.f" "$tmp/hits"
fi
cut -f4 "$tmp/hits" | sort -u | while IFS= read -r id; do [ -f "$tmp/v/$id.json" ] || echo "$id"; done | fetch || true

echo "## findings	severity	id	aliases	ecosystem	name	version	fixed	summary"
while IFS="$(printf '\t')" read -r e n v id; do
  [ -f "$tmp/v/$id.json" ] || { printf '\t%s\t\t%s\t%s\t%s\t\tdetails could not be downloaded\n' "$id" "$e" "$n" "$v"; continue; }
  jq -r --arg e "$e" --arg n "$n" --arg v "$v" '
    def norm: ascii_downcase | gsub("[-_.]+"; "-");
    [ (.database_specific.severity // (.severity[0].score // "") ),
        .id,
        ((.aliases // []) | join(",")),
        $e, $n, $v,
        ([.affected[]? | select((.package.ecosystem | split(":")[0]) == $e and (.package.name | norm) == ($n | norm))
          | .ranges[]?.events[]? | .fixed // empty] | unique | join(" ")),
        ((.summary // .details // "") | gsub("[\t\n]+"; " ") | .[0:160]) ] | @tsv' "$tmp/v/$id.json"
done < "$tmp/hits" > "$tmp/rows"

# The same vulnerability often comes from several databases (GHSA-…, PYSEC-…, GO-…) that list
# each other as aliases. Merge them into one row per package version, keeping every fixed version.
# A severity word (CRITICAL/HIGH/…) is preferred over a CVSS vector.
awk -F'\t' -v OFS='\t' '
  { k = $4 FS $5 FS $6; g = ""
    n = split($2 "," $3, ids, ",")
    for (i = 1; i <= n; i++) if (ids[i] != "" && (k SUBSEP ids[i]) in grp) { g = grp[k SUBSEP ids[i]]; break }
    if (g == "") { g = ++ng; row[g] = $0; order[ng] = g }
    else {
      split(row[g], r, "\t")
      if (r[1] ~ /^CVSS/ && $1 !~ /^CVSS/) r[1] = $1
      r[3] = r[3] "," $2 "," $3
      if ($7 != "" && index(" " r[7] " ", " " $7 " ") == 0) r[7] = (r[7] == "" ? $7 : r[7] " " $7)
      row[g] = r[1] OFS r[2] OFS r[3] OFS r[4] OFS r[5] OFS r[6] OFS r[7] OFS r[8]
    }
    for (i = 1; i <= n; i++) if (ids[i] != "") grp[k SUBSEP ids[i]] = g }
  END { for (i = 1; i <= ng; i++) {
          split(row[order[i]], r, "\t")
          m = split(r[3], a, ","); s = ""; delete seen; seen[r[2]]
          for (j = 1; j <= m; j++) if (a[j] != "" && !(a[j] in seen)) { seen[a[j]]; s = (s == "" ? a[j] : s "," a[j]) }
          r[3] = s
          print r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8] } }
' "$tmp/rows" | sort -t "$(printf '\t')" -k4,6 | tee "$tmp/findings"

echo
echo "## locations	ecosystem	name	version	manager	path	ids"
awk -F'\t' 'NR==FNR { k=$4 FS $5 FS $6; ids[k] = ids[k] (ids[k] == "" ? "" : ",") $2   # not (k in ids): mawk creates ids[k] first
                       r = rank($1); if (r > sev[k]) sev[k] = r; next }
            { k=$1 FS $2 FS $3; if (k in ids) print $0 "\t" ids[k] "\t" sev[k] }
  function rank(s) { s = toupper(s); return s=="CRITICAL" ? 4 : s=="HIGH" ? 3 : (s=="MODERATE"||s=="MEDIUM") ? 2 : s=="LOW" ? 1 : 0 }
' "$tmp/findings" "$tmp/pkgs" > "$tmp/locations"
cut -f1-6 "$tmp/locations"

# The thing that is updated as a whole: a Homebrew formula, a pipx / uv tool, a top-level global
# npm package, a Python environment, an app bundle, or a single binary
echo
echo "## units	max_severity	manager	unit	vulnerable_packages	example_ids"
awk -F'\t' -v OFS='\t' '
  { p = $5; u = p
    if (match(p, /\/Cellar\/[^\/]+\//)) u = "brew formula " substr(p, RSTART + 8, RLENGTH - 9)
    else if (match(p, /\/Applications\/[^\/]+\.app/)) u = substr(p, RSTART, RLENGTH)
    else if (match(p, /(pipx\/venvs|uv\/tools)\/[^\/]+/)) u = substr(p, 1, RSTART + RLENGTH - 1)
    else if (match(p, /\/node_modules\/(@[^\/]+\/)?[^\/]+/)) u = substr(p, 1, RSTART + RLENGTH - 1)
    else if (match(p, /\/site-packages\//)) u = substr(p, 1, RSTART + 13)
    k = $4 OFS u
    if (!(k in n)) order[++m] = k
    if (!((k, $2, $3) in seen)) { seen[k, $2, $3]; n[k]++ }
    if (!(k in s) || $7 > s[k]) s[k] = $7
    if (length(ex[k]) < 60) ex[k] = ex[k] (ex[k] == "" ? "" : ",") $6 }
  END { split("unrated LOW MODERATE HIGH CRITICAL", w, " ")
        for (i = 1; i <= m; i++) { k = order[i]; split(ex[k], e, ","); print w[s[k] + 1], k, n[k], e[1] } }
' "$tmp/locations" | sort -t "$(printf '\t')" -k1,1 -s | awk -F'\t' '
  { r = $1=="CRITICAL" ? 0 : $1=="HIGH" ? 1 : $1=="MODERATE" ? 2 : $1=="LOW" ? 3 : 4; print r "\t" $0 }' |
  sort -t "$(printf '\t')" -k1,1n -k5,5nr | cut -f2-
