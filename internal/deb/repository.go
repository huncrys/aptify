package deb

import (
	"fmt"

	"github.com/dpeckett/deb822/types"
	"github.com/dpeckett/deb822/types/arch"
)

type Repository struct {
	Releases []*Release
	dirty    bool `json:"-"`
}

type Release struct {
	types.Release

	Components []*Component
	dirty      bool        `json:"-"`
	parent     *Repository `json:"-"`
}

type Component struct {
	Name          string
	Architectures []*Architecture
	dirty         bool     `json:"-"`
	parent        *Release `json:"-"`
}

type Architecture struct {
	arch.Arch
	Packages []*types.Package
	dirty    bool       `json:"-"`
	parent   *Component `json:"-"`
}

func NewRepository() *Repository {
	return &Repository{
		Releases: make([]*Release, 0),
	}
}

func NewRelease(debRelease types.Release) *Release {
	release := Release{
		Release: debRelease,
	}

	for _, componentName := range debRelease.Components {
		release.AddComponent(NewComponent(componentName))
	}

	return &release
}

func NewComponent(name string) *Component {
	return &Component{
		Name: name,
	}
}

func NewArchitecture(debArch arch.Arch) *Architecture {
	return &Architecture{
		Arch: debArch,
	}
}

func (r *Repository) AddRelease(release *Release) {
	release.parent = r
	r.Releases = append(r.Releases, release)
}

func (r *Release) AddComponent(component *Component) {
	component.parent = r
	r.Components = append(r.Components, component)
}

func (c *Component) AddArchitecture(architecture *Architecture) {
	architecture.parent = c
	c.Architectures = append(c.Architectures, architecture)
}

func (c *Component) addPackage(pkg *types.Package, dirty bool) error {
	for _, candidate := range c.Architectures {
		if candidate.Is(&pkg.Architecture) {
			candidate.Packages = append(candidate.Packages, pkg)
			if dirty {
				candidate.MarkDirty()
			}
			return nil
		}
	}

	return fmt.Errorf("architecture %s not found in component %s", pkg.Architecture, c.Name)
}

func (c *Component) AddPackage(pkg *types.Package) error {
	return c.addPackage(pkg, false)
}

func (c *Component) AddNewArchitecture(architecture *Architecture) {
	c.AddArchitecture(architecture)
	architecture.MarkDirty()
}

func (c *Component) AddNewPackage(pkg *types.Package) error {
	return c.addPackage(pkg, true)
}

func (r *Repository) MarkDirty() {
	r.dirty = true
}

func (r *Release) MarkDirty() {
	r.dirty = true

	if r.parent != nil {
		r.parent.MarkDirty()
	}
}

func (c *Component) MarkDirty() {
	c.dirty = true

	if c.parent != nil {
		c.parent.MarkDirty()
	}
}

func (a *Architecture) MarkDirty() {
	a.dirty = true

	if a.parent != nil {
		a.parent.MarkDirty()
	}
}

func (r *Repository) IsDirty() bool {
	return r.dirty
}

func (r *Release) IsDirty() bool {
	return r.dirty
}

func (c *Component) IsDirty() bool {
	return c.dirty
}

func (a *Architecture) IsDirty() bool {
	return a.dirty
}

func (r *Repository) ClearDirty() {
	r.dirty = false

	for _, release := range r.Releases {
		release.ClearDirty()
	}
}

func (r *Release) ClearDirty() {
	r.dirty = false

	for _, component := range r.Components {
		component.ClearDirty()
	}
}

func (c *Component) ClearDirty() {
	c.dirty = false

	for _, architecture := range c.Architectures {
		architecture.ClearDirty()
	}
}

func (a *Architecture) ClearDirty() {
	a.dirty = false
}
