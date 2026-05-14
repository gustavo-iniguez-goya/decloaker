package decloaker

import (
	"bufio"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/utils"
	"github.com/gustavo-iniguez-goya/go-diskfs"
	"github.com/gustavo-iniguez-goya/go-diskfs/filesystem"
	"github.com/gustavo-iniguez-goya/go-diskfs/filesystem/ext4"
)

func getPathSeparator(path string) string {
	if path == "/" {
		return ""
	}

	return "/"
}

// https://pkg.go.dev/io/fs#ValidPath
func normalizePath(path string) string {
	// when replacing / by ., we end up adding ./ to the path.
	// we need to delete this prefix before passing it to WalkPath()
	if strings.HasPrefix(path, "./") {
		return strings.Replace(path, "./", "", 1)
	}
	if path == "" || path == "/" {
		path = "."
	}
	if len(path) > 1 && path[0] == '/' {
		path = path[1:]
	}

	return path
}

func copyFile(fs filesystem.FileSystem, orig, dest string) error {
	var err error
	var fd filesystem.File
	fd, err = fs.OpenFile(orig, os.O_RDONLY)
	if err != nil {
		return fmt.Errorf("ext4.OpenFile() %s", err)
	}
	defer fd.Close()

	log.Trace("copying file using regular methods")
	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("os.Create() %s", err)
	}
	defer out.Close()

	if _, err = io.Copy(out, fd); err != nil {
		return fmt.Errorf("io.Copy() %s", err)
	}
	err = out.Sync()
	return err
}

func parseEntries(path string, entries []iofs.DirEntry, inode uint64, search string, matchCb func(path string, e iofs.DirEntry)) {
	log.Trace("parseEntries %s, inode=%d, search=%s\n", path, inode, search)
	for _, e := range entries {
		if e.Name() == "." || e.Name() == ".." {
			continue
		}

		pth := "/" + path + "/" + e.Name()
		info, _ := e.Info()
		if inode > 0 {
			ino := info.Sys().(*syscall.Stat_t)
			if ino != nil && ino.Ino == inode {
				matchCb(utils.ToAscii(pth), e)
			}
			// the user wants to search for this inode specifically, so let's stop here.
			continue
		}
		if search == "" {
			matchCb(utils.ToAscii(pth), e)
			continue
		}

		tmpPath := strings.ReplaceAll(pth, "/", "")
		log.Trace("trying to match %s: %s\n", search, tmpPath)
		matched, err := filepath.Match(search, tmpPath)
		if err != nil {
			log.Error("file pattern error: %s\n", err)
			continue
		}
		if matched {
			log.Trace("pattern matched %s: %s\n", search, tmpPath)
			matchCb(utils.ToAscii(pth), e)
			continue
		}
	}

	tmpPath := strings.ReplaceAll(path, "/", "")
	matched, err := filepath.Match(search, tmpPath)
	if err != nil {
		log.Error("file pattern error: %s\n", err)
		return
	}
	if matched {
		matchCb(utils.ToAscii(path), nil)
	}

}

func WalkPath(fs filesystem.FileSystem, path string, sep string, entriesCb func(string, []iofs.DirEntry)) error {
	path = normalizePath(path)
	log.Trace("walking dir %s\n", path)
	entries, err := fs.ReadDir(path)
	if err != nil {
		log.Trace("WalkPath.ReadDir() error: %s\n", err)
		return err
	}

	entriesCb(path, entries)

	for _, e := range entries {
		if e.Name() == "." || e.Name() == ".." {
			continue
		}
		fullPath := utils.ToAscii(path + "/" + e.Name())
		if e.IsDir() {
			WalkPath(fs, fullPath, sep, entriesCb)
			continue
		}
	}

	return nil
}

func Find(
	dev string,
	partition int,
	path string,
	inode uint64,
	search string,
	openMode diskfs.OpenModeOption,
	recursive bool,
	resultsCb func(pth string, stat os.FileInfo),
) {
	log.Debug("Find, dev=%s, partition=%d, path=%s, inode=%d, search=%s, recursive:%v\n", dev, partition, path, inode, search, recursive)
	tempPath := normalizePath(path)
	log.Trace("Opening path %s\n", tempPath)

	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		log.Error("unable to read disk %s\n", dev)
		return
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		log.Error("unable to read disk partition %s, %d: %s\n", dev, partition, err)
		return
	}
	defer fs.Close()

	// print info and exit if path is a file
	stat, err := fs.Stat(tempPath)
	if err != nil {
		log.Error("Unable to stat path %s: %s\n", path, err)
		return
	}
	if !stat.IsDir() {
		resultsCb(utils.ToAscii(path), stat)
		return
	}

	if !recursive {
		entries, err := fs.ReadDir(tempPath)
		if err != nil {
			log.Error("Unable to read path %s: %s\n", path, err)
			return
		}
		parseEntries(path, entries, inode, search,
			func(path string, e iofs.DirEntry) {
				info, _ := e.Info()
				resultsCb(path, info)
			})
		return
	}

	WalkPath(fs, tempPath, "",
		func(dir string, entries []iofs.DirEntry) {
			log.Debug("\n/%s:\n", dir)
			parseEntries(dir, entries, inode, search,
				func(p string, e iofs.DirEntry) {
					log.Debug("Find, walked path: %s\n", path)
					if e == nil {
						resultsCb(p, nil)
						return
					}
					info, _ := e.Info()
					resultsCb(p, info)
				})
		})
	if err != nil {
		log.Warn("Find files warning: %s\n", err)
	}

	return
}

// functions to read files directly from the disk device.

func ReadDir(
	dev string,
	partition int,
	path string,
	openMode diskfs.OpenModeOption,
	recursive bool,
	resultsCb func(string, os.FileInfo),
) {
	tempPath := normalizePath(path)
	pathSeparator := getPathSeparator(path)
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		log.Error("unable to read disk %s\n", dev)
		return
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		log.Error("unable to read disk partition %s, %d: %s\n", dev, partition, err)
		return
	}
	defer fs.Close()

	stat, err := fs.Stat(tempPath)
	if err != nil {
		log.Error("Unable to stat path %s: %s\n", tempPath, err)
		return
	}
	if !stat.IsDir() {
		resultsCb(utils.ToAscii(pathSeparator+path), stat)
		return
	}
	if !recursive {
		entries, err := fs.ReadDir(tempPath)
		if err != nil {
			log.Error("Unable to read path %s: %s\n", tempPath, err)
			return
		}
		for _, e := range entries {
			if e.Name() == "." || e.Name() == ".." {
				continue
			}
			stat, _ := e.Info()
			if err != nil {
				log.Warn("Unable to stat %s? review needed", path)
			}

			resultsCb(utils.ToAscii(path+pathSeparator+e.Name()), stat)
		}
		return
	}

	WalkPath(fs, path, "",
		func(dir string, entries []iofs.DirEntry) {
			log.Log("\n/%s:\n", dir)
			for _, e := range entries {
				if e.Name() == "." || e.Name() == ".." {
					continue
				}
				p := utils.ToAscii("/" + dir + pathSeparator + e.Name())
				info, _ := e.Info()
				resultsCb(p, info)
			}
		})

	if err != nil {
		log.Warn("listDiskFiles warning: %s\n", err)
	}

	return
}

// https://pkg.go.dev/github.com/diskfs/go-diskfs@v1.7.0/filesystem#FileSystem
func Cp(dev string, partition int, orig, dest string, recursive bool, openMode diskfs.OpenModeOption) error {
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		return fmt.Errorf("unable to read disk, %s", err)
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		return fmt.Errorf("unable to read disk partition %s, %d, %s", dev, partition, err)
	}
	defer fs.Close()

	if !recursive {
		err = copyFile(fs, orig, dest)
		return err
	}

	tempOrig := normalizePath(orig)
	tempDest := normalizePath(dest)
	WalkPath(fs, tempOrig, "",
		func(dir string, entries []iofs.DirEntry) {
			newDest := strings.Replace(dir, tempOrig, tempDest, 1)
			log.Trace("%s -> %s\n", dir, newDest)
			for _, e := range entries {
				if e.Name() == "." || e.Name() == ".." {
					continue
				}
				dstCopy := utils.ToAscii("/" + newDest + "/" + e.Name())
				origCopy := utils.ToAscii(dir + "/" + e.Name())
				info, _ := e.Info()
				if info == nil {
					log.Error("unable to obtain stat information: %s\n", origCopy)
					continue
				}
				if info.IsDir() {
					log.Trace("mkdir %s -> %s\n", dstCopy, e.Name())
					er := os.MkdirAll(dstCopy, 0750)
					if er != nil {
						log.Error("unable to create dirs %s\n", dstCopy)
					} else {
						log.Ok("%s\n", dstCopy)
					}

					continue
				}

				log.Trace("copy %s -> %s\n", origCopy, dstCopy)
				if er := copyFile(fs, origCopy, dstCopy); er != nil {
					log.Error("copy error: %s\n", er)
					continue
				}
				log.Ok("%s\n", dstCopy)
			}

		})
	return err
}

func Mv(dev string, partition int, orig, dest string, openMode diskfs.OpenModeOption) error {
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		return fmt.Errorf("unable to read disk, %s", err)
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		return fmt.Errorf("unable to read disk partition %s, %d, %s", dev, partition, err)
	}

	ext4fs, ok := fs.(*ext4.FileSystem)
	if !ok {
		return fmt.Errorf("%s, partition %d, is not a ext4 filesystem", dev, partition)
	}
	defer ext4fs.Close()

	err = ext4fs.Rename(orig, dest)
	if err != nil {
		return fmt.Errorf("rename/move error: %s", err)
	}

	return err
}

// XXX: considered dangerous??
// everytime a file is deleted, it causes inconsistencies on ext4 filesystemsthe system complains on bad sectors, etc
func Rm(dev string, partition int, paths []string, openMode diskfs.OpenModeOption) error {
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		return fmt.Errorf("unable to read disk, %s", err)
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		return fmt.Errorf("unable to read disk partition %s, %d, %s", dev, partition, err)
	}

	var er error
	var err_paths string
	for _, p := range paths {
		err := fs.Remove(p)
		if err != nil {
			err_paths = err_paths + " " + p
			er = err
		}
	}
	if er != nil {
		err = fmt.Errorf("unable to copy the following paths:\n%s\n", err_paths)
	}

	return err
}

func Stat(dev string, partition int, paths []string, openMode diskfs.OpenModeOption) ([]os.FileInfo, error) {
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read disk, %s", err)
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		return nil, fmt.Errorf("unable to read disk partition %s, %d, %s", dev, partition, err)
	}
	defer fs.Close()

	var list []os.FileInfo
	for _, p := range paths {
		stat, err := fs.Stat(p)
		if err != nil {
			log.Error("ext4.Stat() %s\n", err)
			continue
		}
		list = append(list, stat)
	}

	return list, nil
}

func ReadFile(dev string, partition int, path string) ([]byte, error) {
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(diskfs.ReadOnly),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read disk, %s", err)
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		return nil, fmt.Errorf("unable to read disk partition %s, %d, %s", dev, partition, err)
	}

	var fd filesystem.File
	fd, err = fs.OpenFile(path, os.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("ext4.OpenFile() %s\n", err)
	}

	content := []byte{}
	scanner := bufio.NewReader(fd)
	for {
		line, err := scanner.ReadBytes('\n')
		if err != nil || err == io.EOF {
			break
		}
		content = append(content, line...)
	}

	return content, nil
}
