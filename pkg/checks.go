package decloaker

import (
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/gustavo-iniguez-goya/decloaker/pkg/constants"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
)

// CompareFiles checks if 2 directories have the same number of files
func CompareFiles(listFiles bool, orig, expected map[string]os.FileInfo) int {
	hidden := make(map[string]fs.FileInfo)

	if len(orig) == 0 && len(expected) > 0 {
		log.Detection("[!] WARNING: no files returned by the system command. REVIEW\n")
		return constants.FILES_HIDDEN
	}
	for file := range expected {
		if strings.HasPrefix(file, ourProcPath) {
			delete(expected, file)
			delete(orig, file)
		}
	}

	for file, stat := range expected {
		if listFiles && stat != nil {
			log.Log("%s\t%d\t%s\t%s\n",
				stat.Mode(),
				stat.Size(),
				stat.ModTime().Format(time.RFC3339),
				file)
		}

		if statOrig, found := orig[file]; !found {
			log.Trace("hidden file found by path: %s\n", file)
			hidden[file] = stat
			log.Log("\tHIDDEN: %s\n\n", file)
			continue
		} else {
			if statOrig != nil && stat != nil {
				if statOrig.Size() != stat.Size() {
					log.Log("\tWARNING, size differs for %s, expected: %d, %d\n", file, stat.Size(), statOrig.Size())
				}
			}
		}
	}

	// we should not have more files than what ls returns.
	// when scanning /proc, there can be transitional pids though.
	if len(orig) > len(expected) {
		for file, statSrc := range orig {
			if _, found := expected[file]; !found {
				if statSrc != nil {
					log.Debug("??? %s\t%d\t%s\t%s\n",
						statSrc.Mode(),
						statSrc.Size(),
						statSrc.ModTime().Format(time.RFC3339),
						file)
					continue
				}
			}
		}
	}

	ret := constants.OK

	if len(hidden) > 0 {
		ret = constants.FILES_HIDDEN

		log.Detection("\nHIDDEN dirs/files found:\n\n")
		for h, stat := range hidden {
			if stat != nil {
				log.Detection("\t%v\t%d\t%s\t%s\n", stat.Mode(), stat.Size(), stat.ModTime().Format(time.RFC3339), h)
				continue
			}
			log.Debug("\t(stat not available) %s\n", h)
		}
		log.Log("\n")
		log.Info("use \"%s\" to backup the files, or \"%s\" to delete them", "decloaker disk cp <orig> <dest>", "decloaker disk rm <path>")
		log.Log("\n\n")
	} else {
		log.Log("\n")
		log.Info("\tfiles checked (%d/%d)\n", len(orig), len(expected))
		log.Info("\tno hidden dirs/files found\n")
		log.Info("\t(Use ./decloaker disk -d /dev/<disk> ls --compare /path to low-level scan the disk device. Only ext4 filesystems.)\n\n")
	}

	return ret
}

// CheckHiddenFiles checks differences between the ls output and the output of
// Go's standard lib.
func CheckHiddenFiles(paths []string, tool string, deep bool) int {
	ret := constants.OK
	log.Info("Checking hidden files with \"%s\" %q\n\n", tool, paths)

	for _, p := range paths {
		orig, expected := ListFiles(p, tool, deep)
		r := CompareFiles(true, orig, expected)
		orig = nil
		expected = nil

		if r != constants.OK {
			ret = r
		}
	}

	return ret
}
