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

// Package s3test serves a bucket in process, so that the S3 backend and the
// pipeline running on top of it can be tested against the requests the SDK
// actually sends rather than against a stubbed client.
package s3test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"oaklab.hu/debian/aptify/internal/repofs"
)

// Bucket is an empty bucket and a client addressing it.
type Bucket struct {
	Client *s3.Client
	Name   string
}

// New starts a fake S3 service holding one empty bucket, torn down with the
// test.
func New(t *testing.T) Bucket {
	t.Helper()

	server := httptest.NewServer(gofakes3.New(s3mem.New()).Server())
	t.Cleanup(server.Close)

	client := s3.New(s3.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("key", "secret", ""),
		BaseEndpoint: aws.String(server.URL),
		UsePathStyle: true,
		// The same relaxation the CLI makes: the checksum headers newer SDKs
		// send by default are not understood by every implementation.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})

	const name = "aptify-test"

	if _, err := client.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: aws.String(name),
	}); err != nil {
		t.Fatalf("failed to create the test bucket: %v", err)
	}

	return Bucket{Client: client, Name: name}
}

// FS is a repository published to the root of a fresh bucket.
func FS(t *testing.T) repofs.FS {
	t.Helper()

	bucket := New(t)

	return repofs.NewS3(context.Background(), bucket.Client, bucket.Name, "")
}
