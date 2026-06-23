package dockerimage

import "github.com/8linkz-sec/packmon/internal/domain"

type SourceType string

const (
	SourceDockerfile SourceType = "dockerfile"
	SourceCompose    SourceType = "compose"
)

type Image struct {
	Ref        Ref
	SourceFile string
	SourceType SourceType
	Scope      string
	Relation   string
	Direct     bool
	Indirect   bool
	LocalBuild bool
	Flags      []string
}

func (i Image) Package() domain.Package {
	return domain.Package{
		Name:      i.Ref.Name,
		Version:   i.Ref.Reference,
		Ecosystem: domain.EcosystemDocker,
		Direct:    i.Direct,
		Indirect:  i.Indirect,
	}
}
