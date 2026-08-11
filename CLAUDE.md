# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`aptify` is a single-binary CLI that turns a set of `.deb` files into a signed APT
repository (pool + `dists/` indices + `InRelease`), in a local directory or straight into
an S3 bucket. It is a fork of `github.com/dpeckett/aptify` (kept as the `upstream`
remote), published as `oaklab.hu/debian/aptify`. AGPL-3.0-or-later; every source file
carries the SPDX header and license block - copy it into new files.

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

`-d` also takes an `s3://bucket/prefix` URL, and the whole pipeline then runs against the
bucket. For a self-hosted implementation (Garage, SeaweedFS, Ceph, RustFS) point
`AWS_ENDPOINT_URL` at it; everything else comes from the standard AWS credential chain.

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
pin the no-churn invariant); both are thin wrappers over `verifyRepoFS`/`snapshotTreeFS`,
which take an `fs.FS` so `e2e_s3_test.go` runs the same checks against a bucket. No
container is needed - the fake in `internal/repofs/s3test` is in process.

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
the tests. Where the repository is published is `Options.FS`, a `repofs.FS` (see
[Storage](#storage)) - the pipeline never touches `os` for anything it publishes. The
build is a single pass over the config with these stages, in order:

1. **Load existing state.** Every `dists/*/*/binary-*/Packages` is decoded back into
   `types.Package` and keyed by `"<release>/<component>"`. This is what makes builds
   incremental - the repository itself is the state store, there is no database.
   `--reread` re-extracts control metadata from the pool for those packages while
   keeping their recorded `Filename`, `Size` and `SHA256`.
2. **Ingest.** Config globs are expanded, metadata read from each `.deb`, and packages
   copied into `pool/<component>/<prefix>/<source>/`. A package already present with a
   matching SHA256 is skipped; a mismatch logs a warning and overwrites. `prefix` is the
   first letter of the source name, or `lib?` for a `lib*` long enough to have one -
   standard Debian pool layout. The file itself is `<binary>_<version without
   epoch>_<arch>.deb`, dpkg-name's convention, which keeps the colon of an epoch out of
   the URL apt fetches; only new ingests compute a path, a published package keeps the
   `Filename` its stanza records.
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

`writeIndiceFile` compresses into a buffer, compares against what is published and skips
a write whose bytes would be identical; a real write replaces the file rather than
rewriting it in place, because a by-hash entry serves the published bytes. Every writer
therefore reports *whether the bytes changed*, and that is what sets `modified` -
regenerating an index with the same content does not republish the release. It also
returns the `hashsum.Sums` of the published bytes, hashed off the comparison read when
nothing changed and off the new buffer when it did; `indices.go` collects them per
release, `binary-*/Release` stubs included.

`writeReleaseFile` decodes the existing `InRelease` (verifying against the signing key)
and compares every metadata field; it rewrites only when something changed, an index was
regenerated, the existing stanza lacks a hash list, or a by-hash entry it names has gone
missing. `Release`, `Release.gpg` (detached, pinned to the primary key) and `InRelease`
are all written, from one marshalled buffer so they cannot disagree, and `InRelease`
last because it is what apt prefers.

Its file list is globbed with `releaseIndiceGlobs` (`*/binary-*/Packages*`,
`*/binary-*/Release`, `*/Contents-*`); anything new that apt must verify has to be added
to that glob list or it will be signed for but unlisted, and widening it to
`*/binary-*/*` would list the by-hash entries themselves. `releaseSums` then takes each
checksum from the cheapest source describing those very bytes: the sums this build
collected, else the entry in the verified existing `InRelease` (only when all three
algorithms describe it at one size, so a release published by an older aptify supplies
nothing half-formed), else a read. `--force` reads and hashes everything, which is the
way out if the published bytes are suspect. The list is sorted by name, which is the
order the directory walk it replaced produced - changing it would republish every
existing repository for nothing.

### by-hash

Off unless `by_hash.enabled` is set (`conf.ByHashEnabled()`), and wholly inert when off.
Each listed index is `Clone`d to `dirname(index)/by-hash/<MD5Sum|SHA1|SHA256>/<hex>` - a
hard link locally, a server-side copy on S3 - so a client that read a release can still
fetch what it names after a later build replaced the index. Cloning happens *before* the
release is signed - the flag must never be live over an incomplete tree - and the prune
*after* it, so a crash never destroys a blob the live `InRelease` still names. An entry's
mtime is when its content was created, not when it stopped being current, so
`pruneByHash` touches it (`fsys.Chtimes`) as it leaves the release and only deletes it
`by_hash.retention` (7 days by default) later; Contents entries live in the
component-level `by-hash/`, which is why the sweep walks every directory rather than only
`binary-*`. Turning the feature off emits no flag and then deletes every tree, in that
order.

by-hash covers only the indices the Release lists. Pool `.deb`s are fetched by their
canonical path, so replacing one under an unchanged filename still breaks clients with
stale lists until they `apt-get update` - a rebuilt package wants a version bump.

Timestamps are preserved deliberately (pool copies carry the source file's mtime,
changelog mtimes come from the archive, `signing_key.asc` from the private key) so that
re-running a build does not churn a mirrored repository.

### Changelogs

`deb.GetPackageChangelog` walks the package's `data.tar`, trying
`usr/share/doc/{name,source}/changelog{.Debian,}.gz`; a symlinked doc directory returns
`ErrChangelogSymlink`, and a `.deb` that cannot be opened at all `ErrPackageUnreadable`.
Both "nothing to extract" cases - a missing changelog (`os.ErrNotExist`) and the symlink -
fall back to `placeholderChangelog`, which writes one synthetic entry through
`deb822/changelog` so the `Changelogs:` URL advertised in the Release file still resolves
to something apt can parse; both carry the `.deb`'s own mtime, which is what dates the
published file. `ErrPackageUnreadable` is the one case that warns and publishes nothing:
a vanished pool file is not a package without a changelog, and a placeholder would assert
the version has nothing to report. Changelog paths are keyed by *source* package, so
every binary package of one source competes for a single file; `preferChangelogSource`
picks the one named after the source, else the lexicographically smallest name, so a
dbgsym (whose doc directory is a symlink) never shadows the real changelog whatever order
the component lists them in. The placeholder's exact output is pinned
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

`internal/deb` takes `(fsys fs.FS, name string)` - a package is read wherever it lives -
opens the `.deb` as an ar archive (`archivefs/arfs`), checks `debian-binary` is `2.0`,
and decompresses `control.tar*` / `data.tar*` with `uncompr` (which sniffs the
compression). `arfs` and `tarfs` need an `io.ReaderAt`: `openPackage` hands the opened
file straight over when it is one (osfs) and otherwise spills it to a scratch file, and
`tarfs` gets control archives buffered in memory and data archives spilled - keep that in
mind before adding another full-archive read to the hot path.

The build avoids those reads rather than making them cheap. `b.poolFile(poolPath)`
returns the *local source file* for anything this build ingested (`b.sourcePaths`, filled
in by the ingest), so `Contents`, the changelogs and the backfill read a package aptify
just uploaded from disk instead of fetching it back. Only `--reread`, and the backfill of
a repository published by an older aptify, genuinely read the pool.

## Storage

`internal/repofs` is where a repository is published. `FS` is `io/fs` for reads
(`Open`/`Stat`/`ReadDir`/`Glob`) plus a small write surface shaped by the pipeline:
`WriteFile`, `WriteFrom` (streams a pool `.deb`), `MkdirAll`, `Remove`, `RemoveAll`,
`Clone` (makes a second name serve a file's bytes cheaply) and `Chtimes` (records an
mtime). Every name is repository-relative and slash separated - build them with
`path.Join`, never `filepath.Join`; `osfs` converts at its own boundary and nowhere else.

- `osfs` (`repofs.NewOS`) is a local directory. `WriteFile`/`WriteFrom` go through a
  dot-prefixed temporary and a rename, never a truncate, because a by-hash entry hard
  links the published file and the temporary must not match a Release glob; `Clone` is
  `os.Link`, `Chtimes` is `os.Chtimes`.
- `s3fs` (`repofs.NewS3`) is a bucket. A PUT is atomic per key, so there is no temporary;
  `WriteFrom` goes through `feature/s3/transfermanager`, which splits a pool `.deb` over
  its threshold across a multipart upload (a single PUT caps out at 5 GiB) and has to be
  told not to send checksum headers, since its own setting overrides the client's;
  `Clone` is a server-side `CopyObject`, `Chtimes` a self-copy with the metadata replaced,
  `MkdirAll` a no-op, `RemoveAll` a listing plus batched `DeleteObjects` whose `NoSuchKey`
  error entries are successes - the name's own key is one, and not every implementation
  reports a delete of a missing key the way Amazon does. Modification
  times live in the `mtime` object metadata as Unix `seconds[.fraction]` (rclone's and
  s3cmd's convention, parsed as two ints - never a float64), falling back to
  `LastModified`; `Stat` reports the recorded one, a `ReadDir` entry only what the listing
  carries. A missing object *must* surface as `fs.ErrNotExist` - `load.go`, `byhash.go`
  and `contents.go` branch on it.
- `repofs.New(ctx, target)` picks between them: `s3://bucket/prefix` is a bucket,
  anything else a directory. Credentials, region and endpoint come from the standard AWS
  chain; a custom `AWS_ENDPOINT_URL` turns on path-style addressing, overridable with the
  `path_style` query parameter. The region falls back to `us-east-1` and has to match
  what a self-hosted server is configured with (Garage's `s3_region`), or every request
  fails with `AuthorizationHeaderMalformed`.

`internal/repofs/s3test` serves a bucket in process (`gofakes3`), which is what the
`internal/repo` S3 end-to-end tests build against: the same `verifyRepoFS` and
`snapshotTreeFS` helpers as the local suite, plus a counting wrapper FS asserting that an
unchanged rebuild issues no write, clone, delete, touch or pool read.