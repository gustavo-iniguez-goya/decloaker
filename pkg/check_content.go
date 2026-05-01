package decloaker

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/gustavo-iniguez-goya/decloaker/pkg/constants"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
	sys "github.com/gustavo-iniguez-goya/decloaker/pkg/sys"
)

// XXX: a file may have changed when reading it with cat and later with syscalls.
func CheckHiddenContent(paths []string) int {
	//Info("checking hidden files under %v\n", paths)
	ret := constants.OK

	for _, f := range paths {
		hiddenFound := false

		stat, err := os.Stat(f)
		if err != nil {
			log.Error("Unable to stat %s\n", err)
			continue
		}
		if !stat.Mode().IsRegular() {
			log.Info("Excluding irregular: %s\n", f)
			continue
		}

		log.Info("Checking for hidden content %s\n", f)
		fileContent := sys.Cat("cat", f)
		fileSize := len(fileContent[f])

		raw, err := ioutil.ReadFile(f)
		expectedSize := len(raw)
		expected := string(raw)
		if err != nil {
			log.Warn("%s cannot be read\n", f)
		} else {
			// XXX: sizes may differ if the file is a symbolic link to /proc, like /etc/mtab
			if !strings.HasPrefix(f, "/proc") && stat.Size() != int64(expectedSize) {
				log.Detection("\n=== CONTENT WARNING (read) %s ===\n", f)
				log.Detection("size differs (content: %d, stat.size: %d, symlink: %v), %s\n", expectedSize, stat.Size(), stat.Mode(), f)
				log.Detection("====================================\n")
				ret = constants.CONTENT_HIDDEN
			}
			ret = CompareContent(f, fileContent[f], expected, fileSize, expectedSize, "read")
			hiddenFound = ret == constants.CONTENT_HIDDEN
		}

		// don't mmap /proc or /dev/shm
		if strings.HasPrefix(f, "/proc") || strings.HasPrefix(f, "/dev/shm") {
			continue
		}
		mmSize, mData, err := MmapFile(f)
		if err != nil {
			log.Warn("mmap: %s\n", err)
			continue
		}

		// if we haven't found anything, try it with mmap
		if !hiddenFound {
			if mmSize != int64(expectedSize) {
				log.Detection("\n=== CONTENT WARNING (mmap) %s ===\n", f)
				log.Detection("size differs (content: %d, mmap.size: %d, %s)\n", expectedSize, mmSize, f)
				log.Log("====================================\n")
				ret = constants.CONTENT_HIDDEN
			}

			ret = CompareContent(f, mData, expected, int(mmSize), expectedSize, "mmap")
			hiddenFound = ret == constants.CONTENT_HIDDEN
		}
	}

	if ret == constants.OK {
		log.Info("no hidden content found\n\n")
	}

	return ret
}

func CompareContent(file, orig, expected string, origSize, expectedSize int, tag string) int {
	ret := constants.OK

	if expected != orig {
		ret = constants.FILES_HIDDEN
		log.Detection("\n=== CONTENT WARNING (%s) %s ===\n", tag, file)
		log.Detection("cat content (%d bytes):\n %v\n", origSize, orig)
		log.Detection("-----------------------------------------------------------------\n")
		log.Detection("Go read content (%d bytes):\n %s\n", expectedSize, expected)
		log.Detection("====================================\n")

		ret = constants.FILES_HIDDEN
	}

	return ret
}
