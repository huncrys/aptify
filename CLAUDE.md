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
   `types.Package.Compare`) into a removed set. `surplusVersions` judges a package the
   way a client sees it: because architecture `all` packages are folded into every
   architecture's index, they compete with each architecture's own versions, and one is
   dropped only when it is surplus for *every* architecture publishing it. Keeping an
   `all` version another architecture still needs can leave one architecture above
   `max_versions` - there is a single entry to keep or drop, not one per architecture.
4. **Write indices.** Per release/component/architecture: `Packages`, `Packages.gz`,
   `Packages.xz`, and both `Contents-<arch>` and `Contents-<arch>.gz`. Every index has to
   be published under its uncompressed name too: apt resolves a target by the uncompressed
   key in the Release file and only then picks a compressed variant to fetch, so an index
   listed only as `.gz` is silently never acquired (this is what kept `apt-file` from
   seeing `Contents`).

   Architecture `all` packages are folded into every architecture's index and `all` is
   *not* published as an architecture of its own - Ubuntu's layout, not Debian's, which
   publishes `binary-all` on top of the fold. The exception is a component that has no
   other architecture, which would otherwise get no indices at all. `removeArchIndices`
   deletes the `binary-all` and `Contents-all*` an older version left behind, and the
   component is then rewritten from its full package list rather than incrementally, so
   nothing that only lived in those indices is lost.
5. **Garbage-collect the pool.** `poolCandidates` collects every pool path seen while
   loading and ingesting; `poolReferences` is then counted from the *final* package
   lists, and a candidate nobody references is deleted. Counting incrementally as
   packages are read and pruned is what used to leak: a package listed once per
   architecture was counted several times but removed once, so its `.deb` stayed
   referenced forever. A `.deb` shared by several components is copied once and counted
   once per component, so it survives as long as any component still lists it.
6. **Changelogs** (only when `changelogs: true` *and* `url` is set - `HasChangelogs()`),
   then `signing_key.asc`.

### Incrementality

This is the subtlety most changes have to respect. The `Packages` indices are skipped
when a release/component/arch has no new and no removed packages, unless `--force`. The
`Contents` indice is additionally skipped when there are no *new* packages, which is a
known gap: removals do not currently rewrite `Contents` (see the TODO in the arch loop).
It is rewritten anyway when `contentsIndiceComplete` finds a variant missing, so a
repository published before both variants were written heals itself on the next build.
`Contents` is rebuilt by reading the existing indice, dropping each new package's
previous entries by qualified name, then inverting path -> packages.

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