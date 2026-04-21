package decloaker

import (
	"bufio"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/utils"
	"github.com/gustavo-iniguez-goya/go-diskfs"
	"github.com/gustavo-iniguez-goya/go-diskfs/filesystem"
	"github.com/gustavo-iniguez-goya/go-diskfs/filesystem/ext4"
	"github.com/gustavo-iniguez-goya/go-diskfs/filesystem/xfs"
)

func parseEntries(path string, entries []iofs.DirEntry, inode uint64, search string, matchCb func(path string, e iofs.DirEntry)) {
	for _, e := range entries {
		if e.Name() == "." || e.Name() == ".." {
			continue
		}

		pth := path + "/" + e.Name()
		if inode > 0 {
			info, _ := e.Info()
			ino := info.Sys().(*syscall.Stat_t)
			if ino.Ino == inode {
				matchCb(utils.ToAscii(pth), e)
				continue
			}
		}
		if search == "" {
			continue
		}
		matched, err := filepath.Match(search, e.Name())
		if matched {
			//list[utils.ToAscii(pth)] = e
			matchCb(utils.ToAscii(pth), e)
			continue
		}
		if err != nil {
			log.Error("file pattern error: %s\n", err)
			return
		}
	}
}

func Find(dev string, partition int, path string, inode uint64, search string, openMode diskfs.OpenModeOption, recursive bool) map[string]os.FileInfo {
	if path[len(path)-1] == '/' {
		path = path[0 : len(path)-1]
	}

	list := make(map[string]os.FileInfo)
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		log.Error("unable to read disk %s\n", dev)
		return list
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		log.Error("unable to read disk partition %s, %d: %s\n", dev, partition, err)
		return list
	}
	defer fs.Close()

	if !recursive {
		entries, err := fs.ReadDir(path)
		if err != nil {
			return list
		}
		parseEntries(path, entries, inode, search,
			func(path string, e iofs.DirEntry) {
				info, _ := e.Info()
				list[path] = info
			})
		return list
	}

	WalkPath(fs, path, "",
		func(dir string, entries []iofs.DirEntry) {
			log.Debug("reading path %s\n", dir)
			parseEntries(dir, entries, inode, search,
				func(path string, e iofs.DirEntry) {
					info, _ := e.Info()
					list[path] = info
				})
		})
	if err != nil {
		log.Warn("Find files warning: %s\n", err)
	}

	return list
}

// functions to read files directly from the disk device.

func ReadDir(dev string, partition int, path string, openMode diskfs.OpenModeOption, recursive bool) map[string]os.FileInfo {
	tempPath := path
	if path[len(path)-1] == '/' {
		tempPath = path[0 : len(path)-1]
	}
	// https://pkg.go.dev/io/fs#ValidPath
	if path[0] == '/' {
		tempPath = path[1:]
	}
	if path == "/" {
		tempPath = "."
	}

	list := make(map[string]os.FileInfo)
	disk, err := diskfs.Open(
		dev,
		diskfs.WithOpenMode(openMode),
	)
	if err != nil {
		log.Error("unable to read disk %s\n", dev)
		return list
	}
	defer disk.Close()

	fs, err := disk.GetFilesystem(partition)
	if err != nil {
		log.Error("unable to read disk partition %s, %d: %s\n", dev, partition, err)
		return list
	}
	defer fs.Close()

	if !recursive {
		stat, err := fs.Stat(tempPath)
		if err != nil {
			log.Error("Unable to stat path %s: %s\n", tempPath, err)
			return list
		}
		if !stat.IsDir() {
			list[utils.ToAscii(path)] = stat
			return list
		}

		entries, err := fs.ReadDir(tempPath)
		if err != nil {
			log.Error("Unable to read path %s: %s\n", tempPath, err)
			return list
		}
		for _, e := range entries {
			if e.Name() == "." || e.Name() == ".." {
				continue
			}
			stat, err := fs.Stat(path)
			if err != nil {
				log.Warn("Unable to stat %s? review needed", path)
			}

			list[utils.ToAscii(path+"/"+e.Name())] = stat
		}
		return list
	}

	WalkPath(fs, path, "",
		func(dir string, entries []iofs.DirEntry) {
			log.Debug("reading path %s\n", dir)
			for _, e := range entries {
				if e.Name() == "." || e.Name() == ".." {
					continue
				}
				p := utils.ToAscii(dir + "/" + e.Name())
				info, _ := e.Info()
				list[p] = info
				log.Log("%v\t%d\t%s\t%s\n", info.Mode(), info.Size(), info.ModTime().Format(time.RFC3339), info.Name())
			}
		})
	if err != nil {
		log.Warn("listDiskFiles warning: %s\n", err)
	}

	return list
}

func WalkPath(fs filesystem.FileSystem, path string, sep string, callback func(string, []iofs.DirEntry)) error {
	//Log("reading dir %s\n\n", path)
	entries, err := fs.ReadDir(path)
	if err != nil {
		return err
	}
	callback(path, entries)

	for _, e := range entries {
		if e.Name() == "." || e.Name() == ".." {
			continue
		}
		fullPath := utils.ToAscii(path + "/" + e.Name())
		if e.IsDir() {
			WalkPath(fs, fullPath, sep, callback)
			continue
		}
	}

	return nil
}

// https://pkg.go.dev/github.com/diskfs/go-diskfs@v1.7.0/filesystem#FileSystem
func Cp(dev string, partition int, orig, dest string, openMode diskfs.OpenModeOption) error {
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

	var fd filesystem.File

	switch fs.(type) {
	case *ext4.FileSystem:

		ext4fs, ok := fs.(*ext4.FileSystem)
		if !ok {
			return fmt.Errorf("%s, partition %d, is not a ext4 filesystem", dev, partition)
		}
		defer ext4fs.Close()

		var err error
		fd, err = ext4fs.OpenFile(orig, os.O_RDONLY)
		if err != nil {
			return fmt.Errorf("ext4.OpenFile() %s", err)
		}
	case *xfs.FileSystem:
		xfs, ok := fs.(*xfs.FileSystem)
		if !ok {
			return fmt.Errorf("%s:%d is not a xfs filesystem", dev, partition)
		}
		defer xfs.Close()
		var err error
		fd, err = xfs.OpenFile(orig, os.O_RDONLY)
		if err != nil {
			return fmt.Errorf("xfs.OpenFile() %s", err)
		}

	default:
		return fmt.Errorf("unknown filesysem %v", fs)
	}
	defer fd.Close()

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
		return fmt.Errorf("renme/move error: %s", err)
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

	ext4fs, ok := fs.(*ext4.FileSystem)
	if !ok {
		return fmt.Errorf("%s, partition %d, is not a ext4 filesystem", dev, partition)
	}
	defer ext4fs.Close()

	var er error
	for _, p := range paths {
		log.Info("removing %s: ", p)
		err := ext4fs.Remove(p)
		if err != nil {
			er = err
			log.Log("%s (verify that the path is a ext4 filesystem)\n", err)
		}
	}
	if er != nil {
		er = fmt.Errorf("unable to copy some paths")
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

	var list []os.FileInfo

	switch fs.(type) {
	case *ext4.FileSystem:
		ext4fs, ok := fs.(*ext4.FileSystem)
		if !ok {
			return nil, fmt.Errorf("%s:%d is not a ext4 filesystem", dev, partition)
		}
		defer ext4fs.Close()

		for _, p := range paths {
			stat, err := ext4fs.Stat(p)
			if err != nil {
				log.Error("ext4.Stat() %s\n", err)
				continue
			}
			list = append(list, stat)
		}
	case *xfs.FileSystem:
		xfs, ok := fs.(*xfs.FileSystem)
		if !ok {
			return nil, fmt.Errorf("%s:%d is not a xfs filesystem", dev, partition)
		}
		defer xfs.Close()

		for _, p := range paths {
			stat, err := xfs.Stat(p)
			if err != nil {
				log.Error("xfs.Stat() %s\n", err)
				continue
			}
			list = append(list, stat)
		}
	default:
		return list, fmt.Errorf("%v not implemented yet", fs.Type())
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

	content := []byte{}
	var fd filesystem.File

	switch fs.(type) {
	case *ext4.FileSystem:
		ext4fs, ok := fs.(*ext4.FileSystem)
		if !ok {
			return nil, fmt.Errorf("%s:%d is not a ext4 filesystem", dev, partition)
		}
		defer ext4fs.Close()

		var err error
		fd, err = ext4fs.OpenFile(path, os.O_RDONLY)
		if err != nil {
			return nil, fmt.Errorf("ext4.OpenFile() %s\n", err)
		}

	case *xfs.FileSystem:
		xfs, ok := fs.(*xfs.FileSystem)
		if !ok {
			return nil, fmt.Errorf("%s:%d is not a xfs filesystem", dev, partition)
		}
		defer xfs.Close()
		var err error
		fd, err = xfs.OpenFile(path, os.O_RDONLY)
		if err != nil {
			return nil, fmt.Errorf("xfs.OpenFile() %s\n", err)
		}
	default:
		return nil, fmt.Errorf("%v not implemented\n", fs)
	}
	defer fd.Close()

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
