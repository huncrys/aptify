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
go test -run TestPlaceholderChangelog ./internal/repo   # single test
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
what exercises the arch-`all`, multi-version and source-package paths. Note the three
fixture versions ship identical file lists, so a test that needs `Contents` to differ
between versions builds a synthetic `.deb` via `buildTestDeb` in
`internal/repo/helpers_test.go` instead.

Tests use testify. The e2e suite (`internal/repo/e2e_*.go`) drives `repo.Build`
in-process against the fixtures, signing with the committed test key
`testdata/keys/test_private.asc` (a fixture, deliberately public). The harness in
`helpers_test.go` provides `verifyRepo` (decodes `InRelease` against that key and checks
every listed checksum and compression variant) and `snapshotTree` (byte+mtime maps that
pin the no-churn invariant).

CI (`.gitlab-ci.yml`) is two `oaklab/ci-templates` components: `goreleaser-test`
(gotestsum over `./...` with coverage) and `goreleaser-release`. Releases are cut by
pushing a `vX.Y.Z` tag; the version is stamped via ldflags into
`internal/constants.Version`.

## Architecture

`main.go` is only the CLI (urfave/cli command tree, ~190 lines). The pipeline is
`internal/repo`: `Build(Options)` in `build.go` constructs a `build` context holding the
per-`"<release>/<component>"` package maps and runs one stage method per step below, one
file per concern - `load.go`, `ingest.go`, `prune.go`, `indices.go`, `contents.go`,
`release.go`, `byhash.go`, `changelogs.go`, `pool.go`, `file.go`, `inspect.go`. OpenPGP
key generation/loading/writing is `internal/keys`, shared by the CLI, the pipeline and
the tests. The build is a single pass over the config with these stages, in order:

1. **Load existing state.** Every `dists/*/*/binary-*/Packages` is decoded back into
   `types.Package` and keyed by `"<release>/<component>"`. This is what makes builds
   incremental - the repository directory is the state store, there is no database.
   `--reread` re-extracts control metadata from the pool for those packages while
   keeping their recorded `Filename`, `Size` and `SHA256`.
2. **Ingest.** Config globs are expanded, metadata read from each `.deb`, and packages
   copied into `pool/<component>/<prefix>/<source>/`. A package already present with a
   matching SHA256 is skipped; a mismatch logs a warning and overwrites. `prefix` is the
   first letter of the source name, or `lib?` for `lib*` - standard Debian pool layout.
3. **Prune, then backfill.** `max_versions` per component drops the oldest versions (sorted by
   `types.Package.Compare`) into a removed set. `surplusVersions` judges a package the
   way a client sees it: because architecture `all` packages are folded into every
   architecture's index, they compete with each architecture's own versions, and one is
   dropped only when it is surplus for *every* architecture publishing it. Keeping an
   `all` version another architecture still needs can leave one architecture above
   `max_versions` - there is a single entry to keep or drop, not one per architecture.
   `backfillPackageDigests` then fills what older builds did not publish -
   `Description-md5` from the description, `MD5sum` and `SHA1` by re-reading the pool -
   and names the release/components whose `Packages` must therefore be rewritten. The
   ingest fast path keeps the stanza it already has for an unchanged `.deb`, so this is
   the only route by which an existing repository gains the fields; a missing pool file
   warns rather than failing.
4. **Write indices.** Per release/component/architecture: `Packages`, `Packages.gz`,
   `Packages.xz`, both `Contents-<arch>` and `Contents-<arch>.gz`, and the
   `binary-<arch>/Release` stub (`types.ComponentRelease`), which is rendered and
   compared on every build so an older repository grows one. The stub deliberately
   carries only apt's pin keys (Archive, Origin, Label, Version, Component,
   Architecture, plus Acquire-By-Hash) - no Description; neither Debian nor Ubuntu
   ships one there. Every index has to
   be published under its uncompressed name too: apt resolves a target by the uncompressed
   key in the Release file and only then picks a compressed variant to fetch, so an index
   listed only as `.gz` is silently never acquired (this is what kept `apt-file` from
   seeing `Contents`).

   Architecture `all` packages are folded into every architecture's index and `all` is
   *not* published as an architecture of its own - Ubuntu's layout, not Debian's, which
   publishes `binary-all` on top of the fold. The exception is a component that has no
   other architecture, which would otherwise get no indices at all. `removeArchIndices`
   deletes the `binary-all` and `Contents-all*` an older version left behind; `Packages`
   is then rewritten from the component's full package list, and `Contents` picks the
   folded-in names up because it re-reads any name the existing indice does not describe,
   so nothing that only lived in those indices is lost.
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

This is the subtlety most changes have to respect. Both indices are skipped when a
release/component/arch has no new and no removed packages, unless `--force`, `--reread`
or a backfill touched the component. `Contents` is rewritten anyway when
`contentsIndiceComplete` finds a variant
missing, so a repository published before both variants were written heals itself on the
next build.

`Contents` has no version column, so it can only describe one version per name:
`latestPackages` picks the newest one published for the architecture (architecture `all`
folded in), which is the version a client would install. Rebuilding starts from the
existing indice, drops the names the architecture no longer publishes at all, and then
re-reads from the pool only the names whose winner can have changed - the winner is new,
or the build removed a version that outranks it, or the indice does not describe the
name yet. Everything else keeps the paths already recorded, so a build does not re-open
every `.deb`. `--reread` re-reads them all. Entries are dropped by qualified name, so a
package that changed section does not leave a second entry behind; the map is then
inverted path -> packages to write the file.

The consequence worth remembering: adding an *older* version of a package must not
change `Contents`, and pruning the version it described must. Judging by "which packages
did this build touch" gets both wrong, which is what the winner comparison replaced.

`writeIndiceFile` compresses into a buffer, compares against what is on disk and skips a
write whose bytes would be identical; a real write goes through a dot-prefixed temporary
and a rename, never a truncate, because a by-hash entry hard links the published file.
Every writer therefore reports *whether the bytes changed*, and that is what sets
`modified` - regenerating an index with the same content does not republish the release.

`writeReleaseFile` decodes the existing `InRelease` (verifying against the signing key)
and compares every metadata field; it rewrites only when something changed, an index was
regenerated, the existing stanza lacks a hash list, or a by-hash entry it names has gone
missing. `Release`, `Release.gpg` (detached, pinned to the primary key) and `InRelease`
are all written, from one marshalled buffer so they cannot disagree, and `InRelease`
last because it is what apt prefers. Its checksums come from `hashsum.Directory`,
restricted to `releaseIndiceGlobs` (`*/binary-*/Packages*`, `*/binary-*/Release`,
`*/Contents-*`); anything new that apt must verify has to be added to that glob list or
it will be signed for but unlisted, and widening it to `*/binary-*/*` would list the
by-hash entries themselves.

### by-hash

Off unless `by_hash.enabled` is set (`conf.ByHashEnabled()`), and wholly inert when off.
Each listed index is hard linked to `dirname(index)/by-hash/<MD5Sum|SHA1|SHA256>/<hex>`,
so a client that read a release can still fetch what it names after a later build
replaced the index. Linking happens *before* the release is signed - the flag must never
be live over an incomplete tree - and the prune *after* it, so a crash never destroys a
blob the live `InRelease` still names. A hard link's mtime is when its content was
created, not when it stopped being current, so `pruneByHash` touches an entry as it
leaves the release and only deletes it `by_hash.retention` (7 days by default) later;
Contents entries live in the component-level `by-hash/`, which is why the sweep walks
every directory rather than only `binary-*`. Turning the feature off emits no flag and
then deletes every tree, in that order.

by-hash covers only the indices the Release lists. Pool `.deb`s are fetched by their
canonical path, so replacing one under an unchanged filename still breaks clients with
stale lists until they `apt-get update` - a rebuilt package wants a version bump.

Timestamps are preserved deliberately (pool copies via `PreserveTimes`, changelog mtimes
from the archive, `signing_key.asc` mtime from the private key) so that re-running a
build does not churn a mirrored repository.

### Changelogs

`deb.GetPackageChangelog` walks the package's `data.tar`, trying
`usr/share/doc/{name,source}/changelog{.Debian,}.gz`; a symlinked doc directory returns
`ErrChangelogSymlink`. Only a *missing* changelog (`os.IsNotExist`) falls back to
`placeholderChangelog`, which writes one synthetic entry through `deb822/changelog` so
the `Changelogs:` URL advertised in the Release file still resolves to something apt can
parse; `ErrChangelogSymlink` merely warns and writes nothing. Changelog paths are keyed
by *source* package, so a dbgsym stanza processed before its binary package suppresses
that build's changelog for both (the next build self-heals: packages reload from the
sorted indices, where the binary name sorts first) - pinned as current behaviour by
`TestChangelogsSkipSymlinkedDocDirectories`, not endorsed. The placeholder's exact
output is pinned
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