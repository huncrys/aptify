package archivesext

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/blakesmith/ar"
	"github.com/mholt/archives"
)

func init() {
	archives.RegisterFormat(Ar{})
}

type Ar struct {
	// If true, errors encountered during reading or writing
	// a file within an archive will be logged and the
	// operation will continue on remaining files.
	ContinueOnError bool

	// User ID of the file owner
	Uid int

	// Group ID of the file owner
	Gid int
}

func (Ar) extensions() []string { return []string{".ar", ".a", ".deb", ".lib"} }
func (Ar) Extension() string    { return ".ar" }
func (Ar) MediaType() string    { return "application/x-archive" }

func (a Ar) Match(_ context.Context, filename string, stream io.Reader) (archives.MatchResult, error) {
	var mr archives.MatchResult

	// match filename
	for _, ext := range a.extensions() {
		if strings.Contains(strings.ToLower(filename), ext) {
			mr.ByName = true
		}
	}

	// match file header
	if stream != nil {
		r := tar.NewReader(stream)
		_, err := r.Next()
		mr.ByStream = err == nil
	}

	return mr, nil
}

func (a Ar) Archive(ctx context.Context, output io.Writer, files []archives.FileInfo) error {
	aw := ar.NewWriter(output)

	for _, file := range files {
		if err := a.writeFileToArchive(ctx, aw, file); err != nil {
			if a.ContinueOnError && ctx.Err() == nil { // context errors should always abort
				log.Printf("[ERROR] %v", err)
				continue
			}
			return err
		}
	}

	return nil
}

func (a Ar) ArchiveAsync(ctx context.Context, output io.Writer, jobs <-chan archives.ArchiveAsyncJob) error {
	aw := ar.NewWriter(output)

	for job := range jobs {
		job.Result <- a.writeFileToArchive(ctx, aw, job.File)
	}

	return nil
}

func (a Ar) writeFileToArchive(ctx context.Context, aw *ar.Writer, file archives.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err // honor context cancellation
	}

	tarHdr, err := tar.FileInfoHeader(file, file.LinkTarget)
	if err != nil {
		return fmt.Errorf("file %s: creating header: %w", file.NameInArchive, err)
	}
	tarHdr.Name = file.NameInArchive // complete path, since FileInfoHeader() only has base name
	if tarHdr.Name == "" {
		tarHdr.Name = file.Name() // assume base name of file I guess
	}

	hdr := &ar.Header{
		Name:    tarHdr.Name,
		ModTime: tarHdr.ModTime,
		Uid:     tarHdr.Uid,
		Gid:     tarHdr.Gid,
		Mode:    tarHdr.Mode,
		Size:    tarHdr.Size,
	}

	if a.Uid != 0 {
		hdr.Uid = a.Uid
	}
	if a.Gid != 0 {
		hdr.Gid = a.Gid
	}

	if err := aw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("file %s: writing header: %w", file.NameInArchive, err)
	}

	if err := openAndCopyFile(file, aw); err != nil {
		return fmt.Errorf("file %s: writing data: %w", file.NameInArchive, err)
	}

	return nil
}

func openAndCopyFile(file archives.FileInfo, w io.Writer) error {
	fileReader, err := file.Open()
	if err != nil {
		return err
	}
	defer fileReader.Close()
	// When file is in use and size is being written to, creating the compressed
	// file will fail with "archive/tar: write too long." Using CopyN gracefully
	// handles this.
	_, err = io.CopyN(w, fileReader, file.Size())
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}

func (a Ar) Insert(ctx context.Context, into io.ReadWriteSeeker, files []archives.FileInfo) error {
	aw := ar.NewWriter(into)

	for i, file := range files {
		if err := ctx.Err(); err != nil {
			return err // honor context cancellation
		}

		if err := a.writeFileToArchive(ctx, aw, file); err != nil {
			if a.ContinueOnError && ctx.Err() == nil {
				log.Printf("[ERROR] appending file %d into archive: %s: %v", i, file.Name(), err)
				continue
			}
			return fmt.Errorf("appending file %d into archive: %s: %w", i, file.Name(), err)
		}
	}

	return nil
}

// fileIsIncluded returns true if filename is included according to
// filenameList; meaning it is in the list, its parent folder/path
// is in the list, or the list is nil.
func fileIsIncluded(filenameList []string, filename string) bool {
	// include all files if there is no specific list
	if filenameList == nil {
		return true
	}
	for _, fn := range filenameList {
		// exact matches are of course included
		if filename == fn {
			return true
		}
		// also consider the file included if its parent folder/path is in the list
		if strings.HasPrefix(filename, strings.TrimSuffix(fn, "/")+"/") {
			return true
		}
	}
	return false
}

// skipList keeps a list of non-intersecting paths
// as long as its add method is used. Identical
// elements are rejected, more specific paths are
// replaced with broader ones, and more specific
// paths won't be added when a broader one already
// exists in the list. Trailing slashes are ignored.
type skipList []string

func (s *skipList) add(dir string) {
	trimmedDir := strings.TrimSuffix(dir, "/")
	var dontAdd bool
	for i := 0; i < len(*s); i++ {
		trimmedElem := strings.TrimSuffix((*s)[i], "/")
		if trimmedDir == trimmedElem {
			return
		}
		// don't add dir if a broader path already exists in the list
		if strings.HasPrefix(trimmedDir, trimmedElem+"/") {
			dontAdd = true
			continue
		}
		// if dir is broader than a path in the list, remove more specific path in list
		if strings.HasPrefix(trimmedElem, trimmedDir+"/") {
			*s = append((*s)[:i], (*s)[i+1:]...)
			i--
		}
	}
	if !dontAdd {
		*s = append(*s, dir)
	}
}

// fileInArchive represents a file that is opened from within an archive.
// It implements fs.File.
type fileInArchive struct {
	io.ReadCloser
	info fs.FileInfo
}

func (af fileInArchive) Stat() (fs.FileInfo, error) { return af.info, nil }

func (a Ar) Extract(ctx context.Context, sourceArchive io.Reader, handleFile archives.FileHandler) error {
	ard := ar.NewReader(sourceArchive)

	// important to initialize to non-nil, empty value due to how fileIsIncluded works
	skipDirs := skipList{}

	for {
		if err := ctx.Err(); err != nil {
			return err // honor context cancellation
		}

		hdr, err := ard.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if a.ContinueOnError && ctx.Err() == nil {
				log.Printf("[ERROR] Advancing to next file in tar archive: %v", err)
				continue
			}
			return err
		}
		if fileIsIncluded(skipDirs, hdr.Name) {
			continue
		}

		info := arFileInfo{fh: hdr}
		file := archives.FileInfo{
			FileInfo:      info,
			Header:        hdr,
			NameInArchive: hdr.Name,
			Open: func() (fs.File, error) {
				return fileInArchive{io.NopCloser(ard), info}, nil
			},
		}

		err = handleFile(ctx, file)
		if errors.Is(err, fs.SkipAll) {
			// At first, I wasn't sure if fs.SkipAll implied that the rest of the entries
			// should still be iterated and just "skipped" (i.e. no-ops) or if the walk
			// should stop; both have the same net effect, one is just less efficient...
			// apparently the name of fs.StopWalk was the preferred name, but it still
			// became fs.SkipAll because of semantics with documentation; see
			// https://github.com/golang/go/issues/47209 -- anyway, the walk should stop.
			break
		} else if errors.Is(err, fs.SkipDir) && file.IsDir() {
			skipDirs.add(hdr.Name)
		} else if err != nil {
			return fmt.Errorf("handling file: %s: %w", hdr.Name, err)
		}
	}

	return nil
}

type arFileInfo struct {
	fh *ar.Header
}

func (afi arFileInfo) Name() string       { return path.Base(afi.fh.Name) }
func (afi arFileInfo) Size() int64        { return afi.fh.Size }
func (afi arFileInfo) Mode() os.FileMode  { return os.FileMode(afi.fh.Mode) }
func (afi arFileInfo) ModTime() time.Time { return afi.fh.ModTime }
func (afi arFileInfo) IsDir() bool        { return false }
func (afi arFileInfo) Sys() any           { return nil }

// Interface guards
var (
	_ archives.Archiver      = (*Ar)(nil)
	_ archives.ArchiverAsync = (*Ar)(nil)
	_ archives.Extractor     = (*Ar)(nil)
	_ archives.Inserter      = (*Ar)(nil)
)
