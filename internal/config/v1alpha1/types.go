// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
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

package v1alpha1

import (
	"fmt"
	"time"

	"oaklab.hu/debian/aptify/internal/config/types"
)

const APIVersion = "aptify/v1alpha1"

// defaultByHashRetention is how long a superseded by-hash entry is kept once it
// stops being named by the release, when no retention is configured.
const defaultByHashRetention = 7 * 24 * time.Hour

type Repository struct {
	types.TypeMeta `yaml:",inline"`
	// URL is the public URL of the repository.
	URL string
	// Whether to generate changelogs
	Changelogs bool
	// ByHash configures publishing the indices under their checksums as well,
	// so that a client which read a release can still fetch the indices it
	// names after a later build has replaced them.
	ByHash ByHashConfig `yaml:"by_hash,omitempty"`
	// Releases is the list of releases to generate.
	Releases []ReleaseConfig
}

// ByHashConfig is the configuration for by-hash index publishing.
type ByHashConfig struct {
	// Enabled turns by-hash publishing on. Off by default.
	Enabled bool
	// Retention is how long an entry is kept after it stops being named by the
	// release. If not specified, entries are kept for seven days.
	Retention time.Duration
}

// ReleaseConfig is the configuration for a release.
type ReleaseConfig struct {
	// Name is the name of the release.
	Name string
	// Version is the version of the release.
	Version string
	// Origin is the origin of the release.
	// This specifies the source or the entity responsible for creating and distributing the release.
	Origin string
	// Label is the label of the release.
	// This provides a human-readable identifier or tag for the release.
	Label string
	// Suite is the suite of the release.
	// This categorizes the release into a broader collection or group of releases.
	Suite string
	// Description is a description of the release.
	Description string
	// Components is the list of components (and their packages) within the release.
	Components []ComponentConfig
}

// ComponentConfig is the configuration for a component.
type ComponentConfig struct {
	// Name is the name of the component.
	Name string
	// Packages is the list of file system paths/glob patterns to deb files that
	// will be included within the component.
	Packages []string
	// Maximum number of versions to keep for each package in this component.
	// If not specified, all versions will be kept.
	MaxVersions uint `yaml:"max_versions,omitempty"`
}

func (r *Repository) GetAPIVersion() string {
	return APIVersion
}

func (r *Repository) GetKind() string {
	return "Repository"
}

func (r *Repository) PopulateTypeMeta() {
	r.TypeMeta = types.TypeMeta{
		APIVersion: APIVersion,
		Kind:       "Repository",
	}
}

func (r *Repository) HasChangelogs() bool {
	return r.Changelogs && r.URL != ""
}

// ByHashEnabled reports whether the indices are published under their
// checksums as well.
func (r *Repository) ByHashEnabled() bool {
	return r.ByHash.Enabled
}

// ByHashRetention is how long a superseded by-hash entry is kept.
func (r *Repository) ByHashRetention() time.Duration {
	if r.ByHash.Retention <= 0 {
		return defaultByHashRetention
	}

	return r.ByHash.Retention
}

func GetConfigByKind(kind string) (types.Config, error) {
	switch kind {
	case "Repository":
		return &Repository{}, nil
	default:
		return nil, fmt.Errorf("unsupported kind: %s", kind)
	}
}
