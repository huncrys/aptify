# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`aptify` is a single-binary CLI that turns a set of `.deb` files into a signed APT
repository (pool + `dists/` indices + `InRelease`). It is a fork of
`github.com/dpeckett/aptify` (kept as the `upstream` remote), published as
`oaklab.hu/debian/aptify`. AGPL-3.0-or-later; every source file carries the SPDX
header and license block - copy it into new files.

Debian format handling (deb822 encode/decode, `types.Package`, `types.Release`,
version/arch/time types, `Contents` and `changelog` readers and writers) lives in
the sibling library `oaklab.hu/debian/deb822`, not here. Prefer adding format
knowledge there and consuming it, which is what the recent history has been doing.

## Commands

```shell
go build ./...
go test ./...
go test -run TestPlaceholderChangelog .   # single test
go vet ./...
golangci-lint run                         # CI runs this only if the component's lint input is on
```

End-to-end smoke run against the checked-in fixtures (keys live in the gitignored
`.aptify/`, which already holds a dev key; global flags work before or after the
subcommand):

```shell
go run . --config-dir .aptify init-keys --name dev --email dev@example.com
go run . build --config-dir .aptify -c examples/demo.yaml -d ./demo-repo
go run . inspect -d ./demo-repo | jq .
```

`demo-repo/`, `repository/`, `.aptify/` and `dist/` are gitignored; `testdata/package/`
holds `hello-world` 1.0/2.0 (amd64, arm64) and 3.0 (`all`) plus dbgsym packages, which is
what exercises the arch-`all`, multi-version and source-package paths.

CI (`.gitlab-ci.yml`) is two `oaklab/ci-templates` components: `goreleaser-test`
(gotestsum over `./...` with coverage) and `goreleaser-release`. Releases are cut by
pushing a `vX.Y.Z` tag; the version is stamped via ldflags into
`internal/constants.Version`.

## Architecture

Almost all logic is `buildRepository` in `main.go`; `internal/` holds thin helpers.
The build is a single pass over the config with these stages, in order:

1. **Load existing state.** Every `dists/*/*/binary-*/Packages` is decoded back into
   `types.Package` and keyed by `"<release>/<component>"`. This is what makes builds
   incremental - the repository directory is the state store, there is no database.
   `--reread` re-extracts control metadata from the pool for those packages while
   keeping their recorded `Filename`, `Size` and `SHA256`.
2. **Ingest.** Config globs are expanded, metadata read from each `.deb`, and packages
   copied into `pool/<component>/<prefix>/<source>/`. A package already present with a
   matching SHA256 is skipped; a mismatch logs a warning and overwrites. `prefix` is the
   first letter of the source name, or `lib?` for `lib*` - standard Debian pool layout.
3. **Prune.** `max_versions` per component drops the oldest versions (sorted by
   `types.Package.Compare`) into a removed set.
4. **Write indices.** Per release/component/architecture: `Packages`, `Packages.gz`,
   `Packages.xz`, and `Contents-<arch>.gz`. Architecture `all` packages are folded into
   every architecture's index.
5. **Garbage-collect the pool.** `poolReferences` counts how many index entries point at
   each pool path across all releases; files reaching zero are deleted. A `.deb` shared
   by several components is copied once and reference-counted, so any change to how
   packages are added or removed must keep this counter balanced.
6. **Changelogs** (only when `changelogs: true` *and* `url` is set - `HasChangelogs()`),
   then `signing_key.asc`.

### Incrementality

This is the subtlety most changes have to respect. Index generation is skipped when a
release/component/arch has no new and no removed packages, unless `--force`. The
`Contents` indice is additionally skipped when there are no *new* packages, which is a
known gap: removals do not currently rewrite `Contents` (see the TODO in
`writeContentsIndice`). `Contents` is rebuilt by reading the existing indice, dropping
each new package's previous entries by qualified name, then inverting path -> packages.

`writeReleaseFile` decodes the existing `InRelease` (verifying against the signing key)
and compares every metadata field; it rewrites only when something changed or an index
was regenerated. Only `InRelease` is written - no detached `Release`/`Release.gpg`. Its
checksums come from `sha256sum.Directory`, restricted to the globs
`*/binary-*/Packages*` and `*/Contents-*`; anything new that apt must verify has to be
added to that glob list or it will be signed for but unlisted.

Timestamps are preserved deliberately (pool copies via `PreserveTimes`, changelog mtimes
from the archive, `signing_key.asc` mtime from the private key) so that re-running a
build does not churn a mirrored repository.

### Changelogs

`deb.GetPackageChangelog` walks the package's `data.tar`, trying
`usr/share/doc/{name,source}/changelog{.Debian,}.gz`; a symlinked doc directory returns
`ErrChangelogSymlink`. Missing changelogs fall back to `placeholderChangelog`, which
writes one synthetic entry through `deb822/changelog` so the `Changelogs:` URL advertised
in the Release file still resolves to something apt can parse. Its exact output is pinned
by `changelog_placeholder_test.go` - published changelogs must not change shape.
Changelog files are named from the *source* package and version without epoch, and unused
`.changelog` files are pruned by walking `changelogs/`.

### Config

`internal/config` reads YAML by first decoding `apiVersion`/`kind` (Kubernetes-style
TypeMeta), dispatching to the versioned struct, then running `MigrateToLatest`. Only
`aptify/v1alpha1` `Repository` exists; adding a new version means a new
`internal/config/vX` package plus a migration arm, not editing `v1alpha1` in place.
`internal/config/v1alpha1/types.go` is the schema of record referenced by the README.

### deb extraction

`internal/deb` opens the `.deb` as an ar archive (`archivefs/arfs`), checks
`debian-binary` is `2.0`, and decompresses `control.tar*` / `data.tar*` with `uncompr`
(which sniffs the compression). `tarfs` needs a seekable reader, so control archives are
buffered in memory and data archives spilled to a temp file - keep that in mind before
adding another full-archive read to the hot path.