// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Copyright (C) 2026 Kristof Bach <crys@crys.hu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package repofs

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// defaultRegion is what an S3 implementation that does not care about regions
// is addressed with. The SDK insists on having one, while Garage, SeaweedFS,
// Ceph and RustFS will accept whatever they are given.
const defaultRegion = "us-east-1"

// New is the repository a target names: an s3://bucket/prefix URL is a bucket,
// anything else a local directory.
func New(ctx context.Context, target string) (FS, error) {
	if !IsS3URL(target) {
		return NewOS(target), nil
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository URL: %w", err)
	}

	bucket := u.Host
	if bucket == "" {
		return nil, fmt.Errorf("repository URL names no bucket: %s", target)
	}

	client, err := newS3Client(ctx, u)
	if err != nil {
		return nil, err
	}

	return NewS3(ctx, client, bucket, u.Path), nil
}

// IsS3URL reports whether a repository target names a bucket rather than a
// directory.
func IsS3URL(target string) bool {
	return strings.HasPrefix(target, "s3://")
}

// newS3Client builds the client from the standard AWS chain: credentials,
// region and endpoint come from the environment or the shared configuration,
// with AWS_ENDPOINT_URL (or AWS_ENDPOINT_URL_S3) pointing at anything that is
// not Amazon's.
func newS3Client(ctx context.Context, u *url.URL) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}

	pathStyle, err := usePathStyle(u)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = pathStyle

		// The checksum headers newer SDKs send on every request are not
		// understood by every S3 implementation, and nothing here needs them:
		// what a repository publishes is verified by the checksums in its own
		// Release file.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	}), nil
}

// usePathStyle reports whether to address the bucket as a path element rather
// than as a subdomain. A self-hosted endpoint is assumed to want path style,
// which is what Garage, SeaweedFS, Ceph and RustFS are usually reached by; the
// path_style query parameter of the repository URL decides it either way.
func usePathStyle(u *url.URL) (bool, error) {
	if raw := u.Query().Get("path_style"); raw != "" {
		pathStyle, err := strconv.ParseBool(raw)
		if err != nil {
			return false, fmt.Errorf("failed to parse path_style: %w", err)
		}

		return pathStyle, nil
	}

	return os.Getenv("AWS_ENDPOINT_URL") != "" || os.Getenv("AWS_ENDPOINT_URL_S3") != "", nil
}
