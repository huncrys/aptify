package deb

import (
	"fmt"

	"github.com/dpeckett/deb822/types"
	"github.com/dpeckett/deb822/types/arch"
)

type Repository struct {
	Releases []Release
}

type Release struct {
	types.Release

	Components []Component
}

type Component struct {
	Name          string
	Architectures []Architecture
}

type Architecture struct {
	arch.Arch
	Packages []types.Package
}

func NewRepository() *Repository {
	return &Repository{
		Releases: make([]Release, 0),
	}
}

func NewRelease(debRelease types.Release) Release {
	release := Release{
		debRelease,
		make([]Component, 0),
	}

	for _, componentName := range debRelease.Components {
		release.Components = append(release.Components, NewComponent(componentName))
	}

	return release
}

func NewComponent(name string) Component {
	return Component{
		name,
		make([]Architecture, 0),
	}
}

func NewArchitecture(debArch arch.Arch) Architecture {
	return Architecture{
		Arch:     debArch,
		Packages: make([]types.Package, 0),
	}
}

func (r *Repository) AddRelease(debRelease Release) {
	r.Releases = append(r.Releases, debRelease)
}

func (r *Release) AddComponent(component Component) {
	r.Components = append(r.Components, component)
}

func (c *Component) AddArchitecture(debArch arch.Arch) {
	c.Architectures = append(c.Architectures, NewArchitecture(debArch))
}

func (c *Component) AddPackage(pkg types.Package) error {
	for i := range c.Architectures {
		candidate := &c.Architectures[i]
		if candidate.Is(&pkg.Architecture) {
			candidate.Packages = append(candidate.Packages, pkg)

			return nil
		}
	}

	return fmt.Errorf("architecture %s not found in component %s", pkg.Architecture, c.Name)
}
