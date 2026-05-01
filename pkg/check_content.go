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
				r := constants.CONTENT_HIDDEN
				log.Event(log.DETECTION, log.CatHiddenContent,
					"\n=== CONTENT WARNING (%s) ===\nsize differs (content: %d, stat.size: %d, symlink: %v), %s\n====================================\n",
					[]log.Fields{
						{Key: constants.FieldMethod, Value: "read"},
						{Key: constants.FieldContentSize, Value: expectedSize},
						{Key: constants.FieldStatSize, Value: stat.Size()},
						{Key: constants.FieldIsSymlink, Value: stat.Mode()&os.ModeSymlink != 0},
						{Key: constants.FieldPath, Value: f},
					})
				if r != constants.OK {
					ret = constants.CONTENT_HIDDEN
					hiddenFound = true
				}
			}
			ret = CompareContent(f, fileContent[f], expected, fileSize, expectedSize, "read")
			if ret != constants.OK {
				ret = constants.CONTENT_HIDDEN
				hiddenFound = true
			}
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
				log.Event(log.DETECTION, log.CatHiddenContent,
					"\n=== CONTENT WARNING (%s) ===\nsize differs (content: %d, mmap.size: %d, %s)\n====================================\n",
					[]log.Fields{
						{Key: constants.FieldMethod, Value: "mmap"},
						{Key: constants.FieldContentSize, Value: expectedSize},
						{Key: constants.FieldMmapSize, Value: mmSize},
						{Key: constants.FieldPath, Value: f},
					})
				ret = constants.CONTENT_HIDDEN
				hiddenFound = true
			}

			ret = CompareContent(f, mData, expected, int(mmSize), expectedSize, "mmap")
			if ret != constants.OK {
				ret = constants.CONTENT_HIDDEN
				hiddenFound = true
			}
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
		log.Event(log.DETECTION, log.CatHiddenContent,
			"\n=== CONTENT WARNING (%s) %s ===\ncat content (%d bytes):\n %v\n-----------------------------------------------------------------\nGo read content (%d bytes):\n %s\n====================================\n",
			[]log.Fields{
				{Key: constants.FieldMethod, Value: tag},
				{Key: constants.FieldFile, Value: file},
				{Key: constants.FieldOriginalSize, Value: origSize},
				{Key: constants.FieldOriginalContent, Value: orig},
				{Key: constants.FieldExpectedSize, Value: expectedSize},
				{Key: constants.FieldExpectedContent, Value: expected},
			})

		ret = constants.FILES_HIDDEN
	}

	return ret
}
