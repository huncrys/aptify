# aptify

Probably the quickest, and easiest, way to create a Debian APT repository from
a list of deb files.

## Installation

### Go install

```shell
go install oaklab.hu/debian/aptify@latest
```

### GitLab Releases

Download statically linked binaries from the GitLab releases page:

[Latest Release](https://oaklab.hu/debian/aptify/-/releases/permalink/latest)

## Usage

### Initialize Keys

You'll need a GPG key to sign your repository. If you don't have one, you can
create one using the `init-keys` command:

```shell
aptify init-keys
```

The resulting key will be written to your `$XDG_CONFIG_HOME/aptify/` directory. You should back this up somewhere safe.

### Create Repository

You'll need a simple YAML file describing the repository you want to create.

A demonstration file is provided in the examples directory. Schema for the
repository configuration is defined in the
[v1alpha1/types.go](./internal/config/v1alpha1/types.go) file.

```shell
aptify build -c examples/demo.yaml -d ./demo-repo
```

This will create a directory called `demo-repo` containing the repository.

### Publish to S3

`-d` also takes an `s3://bucket/prefix` URL, and the repository is then built
directly in the bucket. The repository itself is the state store either way, so
no local copy is needed: a build reads back the indices it published last time,
uploads what changed and leaves the rest alone.

```shell
aptify build -c examples/demo.yaml -d s3://apt.example.com/debian
aptify inspect -d s3://apt.example.com/debian
```

Credentials, region and endpoint come from the standard AWS chain, so anything
that configures the AWS CLI configures aptify: `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`, `AWS_REGION`, an instance role, or
`~/.aws/config`. A bucket that is not Amazon's - Garage, SeaweedFS, Ceph
(RadosGW), RustFS - is addressed by setting `AWS_ENDPOINT_URL`:

```shell
export AWS_REGION=garage
export AWS_ENDPOINT_URL=https://s3.example.com
aptify build -c examples/demo.yaml -d s3://apt/debian
```

`AWS_REGION` has to name the region the server is configured with (Garage calls
it `s3_region` and defaults it to `garage`); without one aptify falls back to
`us-east-1`, and a mismatch fails at the first request with
`AuthorizationHeaderMalformed`, naming both the region it got and the one it
expected.

A custom endpoint switches bucket addressing to path style, which is what
self-hosted implementations usually expect. Override it either way with the
`path_style` query parameter: `-d 's3://bucket/debian?path_style=false'`.

Modification times are preserved the way rclone and s3cmd preserve them, in the
`mtime` object metadata (`X-Amz-Meta-Mtime`) as Unix seconds with an optional
nanosecond fraction, since S3's own `LastModified` records the upload rather
than the content. That is what keeps a mirror, and the by-hash retention
window, from seeing every rebuild as a change.

Two things to know before pointing a pipeline at it:

- Two builds must not run against one bucket at the same time. There is no
  locking, and the same is true of a local directory today.
- `--reread`, and the one-off backfill of a repository published by an older
  aptify, read the pool: those download every `.deb` they touch. An ordinary
  build never does - a package it just ingested is read from the local file it
  was uploaded from.

### Serve Repository

The recommended way to serve the repository is to use [caddy](https://caddyserver.com).

An example Caddyfile is provided below, replace `apt.example.com` with your domain:

```caddyfile
https://apt.example.com {
  root * /var/lib/aptify/repo
  file_server {
    browse 
  }
}

http://apt.example.com {
  root * /var/lib/aptify/repo

  # Don't serve the signing key over insecure connections.
  handle_path "/signing_key.asc" {
    redir https://{host}{uri}
  }

  handle {
    root * /var/lib/aptify/repo
    file_server {
      browse
    }
  }
}
```

### Use Repository

To use the repository, you'll need to add a new apt source to your system. You
can do this by downloading the signing key and adding the repository to your
`/etc/apt/sources.list.d` directory.

```shell
curl -fsL https://apt.example.com/signing_key.asc | sudo tee /etc/apt/keyrings/demo-repo-keyring.asc > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/demo-repo-keyring.asc] http://apt.example.com/ $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/demo-repo.list > /dev/null
```

Packages can now be installed from the repository.

```shell
sudo apt update
sudo apt install hello-world
```
