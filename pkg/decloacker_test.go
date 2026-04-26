package decloaker

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
)

func init() {
	log.NewLogger(log.PLAIN, "")
}

func TestStat(t *testing.T) {
	paths := []string{"/etc/hosts", "/"}
	files := Stat(paths)

	if len(files) == 0 {
		t.Error("0 files stat-ed")
	}

	for path, st := range files {
		fmt.Printf("path: %s\n\t%s\t%d\t%s\t%s\n",
			path,
			st.Mode(),
			st.Size(),
			st.ModTime().Format(time.RFC3339),
			st.Name(),
		)
		if st == nil || st.Sys() == nil {
			t.Errorf("No Sys() infor for %s", path)
		}
	}
}

func TestCat(t *testing.T) {
	paths := []string{"/etc/hosts"}
	ret := Cat(paths)

	if ret != OK {
		t.Error("Cat returned error")
	}
}

func TestCopy(t *testing.T) {
	orig := "/etc/hosts"
	dest := "/tmp/hosts.bak"
	ret := Copy(orig, dest)
	if ret != OK {
		t.Error("Copy() returned error")
	}

	stOrig, errOrig := os.Stat(orig)
	stDst, errDst := os.Stat(dest)

	if errDst != nil {
		t.Errorf("Error stat-ing %s", errDst)
	}
	if errOrig != nil {
		t.Errorf("Error stat-ing %s", errOrig)
	}

	if stOrig == nil {
		t.Errorf("error stat-ing %s", orig)
	}
	if stDst == nil {
		t.Errorf("error stat-ing %s", dest)
	}

	if stOrig.Size() != stDst.Size() {
		t.Errorf("Size differs %s:%d vs %d:%s", orig, stOrig.Size(), stDst.Size(), dest)
	}
}

func TestDelete(t *testing.T) {
	orig := "/etc/hosts"
	dest := "/tmp/hosts.bak"
	ret := Copy(orig, dest)
	if ret != OK {
		t.Error("error copying file to /tmp")
	}

	ret = Delete([]string{dest})
	if ret != OK {
		t.Errorf("error deleting file %s", dest)
	}
}

func TestRename(t *testing.T) {
	orig := "/etc/hosts"
	dest := "/tmp/hosts.bak"
	ret := Copy(orig, dest)
	if ret != OK {
		t.Error("Copy() returned error")
	}

	newDst := "/tmp/hosts.bak1"
	ret = Rename(dest, newDst)
	if ret != OK {
		t.Error("Rename() returned error")
	}
	time.Sleep(2)

	stOldDst, errOldDst := os.Stat(dest)
	stDst, errDst := os.Stat(newDst)
	if errDst != nil {
		t.Errorf("Error stat-ing %s: %s", stDst, errDst)
	}
	if errOldDst == nil {
		t.Errorf("%s still exists: %v", errOldDst, stOldDst)
	}
}

func TestMmap(t *testing.T) {
	raw, err := ioutil.ReadFile("/etc/hosts")
	expectedSize := len(raw)
	expectedData := string(raw)

	mmSize, mData, err := MmapFile("/etc/hosts")
	if err != nil {
		t.Errorf("mmap error: %s\n", err)
	}

	if mmSize != int64(expectedSize) {
		t.Errorf("mmap size differ, mmap: %d, ReadFile: %d", mmSize, expectedSize)
	}

	if mData != expectedData {
		t.Errorf("mmap data not equal:\nmmap:\n%s\nReadFile:\n%s", mData, expectedData)
	}
}

func TestReadDir(t *testing.T) {
	dir := "/tmp/testdir"
	tests := map[string]int64{
		dir + "/testfile.txt":  5,
		dir + "/testfile1.txt": 6,
		dir + "/testfile2.txt": 7,
	}

	os.RemoveAll(dir)
	err := os.Mkdir(dir, 0750)
	if err != nil {
		t.Errorf("unable to create dir %s", dir)
	}

	i := "X"
	data := "data"
	for file := range tests {
		err = os.WriteFile(file, []byte(fmt.Sprint(data, i)), 0660)
		if err != nil {
			t.Errorf("unable to create file %s", file)
		}
		data += i
	}

	files := ReadDir(dir, true)
	if files == nil {
		t.Errorf("ReadDir returned nil")
	}
	if len(files) == 0 {
		t.Errorf("ReadDir returned 0 files")
	}
	for p, st := range files {
		expectedSize, found := tests[p]
		if !found {
			t.Errorf("%s not found in the expected results", p)
		}
		if expectedSize != st.Size() {
			t.Errorf("%s has unexpected size: %d vs %d", p, st.Size(), expectedSize)
		}
		t.Logf("%s - %d", p, st.Size())
	}
}
