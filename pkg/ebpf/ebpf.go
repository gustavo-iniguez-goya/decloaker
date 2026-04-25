package ebpf

import (
	"bytes"
	_ "embed"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/utils"
)

//go:embed kern/dump_tasks.o
// this line must go here
var dumpTask []byte

//go:embed kern/dump_tasks_5x.o
// this line must go here
var dumpTask5x []byte

//go:embed kern/dump_files.o
var dumpFiles []byte

//go:embed kern/dump_kmods.o
var dumpKmod []byte

var (
	LiveDir   = "/sys/fs/bpf/decloaker"
	TasksPath = "/sys/fs/bpf/decloaker/tasks"
	FilesPath = "/sys/fs/bpf/decloaker/files"
	KmodsPath = "/sys/fs/bpf/decloaker/kmods"
	reTasks   = regexp.MustCompile(`pid=([0-9]+)\sppid=([0-9]+)\sinode=([0-9]+)\suid=([0-9]+)\sgid=([0-9]+)\shost=([0-9A-Za-z_-]+)\scomm=(.{0,16})\sexe=(.*)$`)
	reFiles   = regexp.MustCompile(`pid=([0-9]+)\sppid=([0-9]+)\sfd=([0-9]+)\sinode=([0-9]+)\suid=([0-9]+)\sgid=([0-9]+)\shost=([0-9A-Za-z_-]+)\sfile=(.*)\scomm=(.{0,16})\sexe=(.*)$`)
	// addr=0xffffffffc4668010 atype=T func=hide_proc_modules_init name=lab_hide type=FTRACE_MOD 0x8000
	reKmods         = regexp.MustCompile(`addr=([a-zA-Z0-9]+)\satype=([a-zA-Z0-9])\sfunc=([a-zA-Z0-9\-_]+)\sname=([a-zA-Z0-9\-_]+)\stype=([a-zA-Z0-9\-_]+)`)
	ProgDumpTasks   = "dump_tasks"
	ProgDumpTasks5x = "dump_tasks"
	ProgDumpFiles   = "dump_files"
	ProgDumpKmods   = "dump_kmods"

	progList = map[string][]byte{
		ProgDumpTasks: dumpTask,
		ProgDumpFiles: dumpFiles,
		ProgDumpKmods: dumpKmod,
	}
	progPaths = map[string]string{
		ProgDumpTasks: TasksPath,
		ProgDumpFiles: FilesPath,
		ProgDumpKmods: KmodsPath,
	}
	progHooks = map[string]*link.Iter{}
)

type Task struct {
	Exe      string
	Cmdline  string
	Comm     string
	Hostname string
	Inode    string
	Uid      string
	Gid      string
	Pid      string
	PPid     string
}

func (t *Task) Get(field string) (interface{}, bool) {
	switch field {
	case "exe":
		return t.Exe, true
	case "cmdline":
		return t.Cmdline, true
	case "pid":
		return t.PPid, true
	case "ppid":
		return t.PPid, true
	case "uid":
		return t.Uid, true
	case "gid":
		return t.Gid, true
	case "comm":
		return t.Comm, true
	case "hostname":
		return t.Hostname, true
	case "inode":
		return t.Inode, true
		//case "maps":
		//    return t.Maps, true
		//case "environ":
		//    return t.Environ, true
	}
	return nil, false
}

type File struct {
	Exe      string
	Comm     string
	Hostname string
	File     string
	Uid      string
	Gid      string
	Inode    string
	Fd       string
	Pid      string
	PPid     string
}

func (f *File) Get(field string) (interface{}, bool) {
	switch field {
	case "exe":
		return f.Exe, true
	case "comm":
		return f.Comm, true
	case "hostname":
		return f.Hostname, true
	case "file", "path":
		return f.File, true
	case "uid":
		return f.Uid, true
	case "did":
		return f.Gid, true
	case "inode":
		return f.Inode, true
	case "fd":
		return f.Fd, true
	case "pid":
		return f.Pid, true
	case "ppid":
		return f.PPid, true
	}

	return nil, false
}

type Kmod struct {
	Addr  string
	AType string
	Func  string
	Name  string
	Type  string
}

func ConfigureIters(pinIters bool) {
	if os.Getuid() != 0 {
		log.Warn("[eBPF] execute decloaker as root to use eBPF functionality.\n")
		return
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error("[eBPF] unable to remove memlock? unlikely. Review this system with other utilities, and offline\n")
	}

	var uname unix.Utsname
	unix.Uname(&uname)
	// bpf_d_path() not supported in kernels 5.x
	if uname.Release[0] != '6' {
		progList[ProgDumpTasks] = dumpTask5x
	}

	for progName, code := range progList {
		log.Debug("Loading ebpf module %s\n", progName)

		collOpts := ebpf.CollectionOptions{}
		specs, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(code[:]))
		if err != nil {
			log.Error("[eBPF] module specs error %s: %s\n", progName, err)
			continue
		}
		iterTask, err := ebpf.NewCollectionWithOptions(specs, collOpts)
		if iterTask == nil {
			log.Debug("[eBPF] iter task: %s\n", err)
			continue
		}
		prog := iterTask.Programs[progName]
		if prog == nil {
			log.Error("[eBPF] iter task nil %s: %s\n", progName, err)
			continue
		}

		iter, err := link.AttachIter(link.IterOptions{
			Program: prog,
		})
		if err != nil {
			log.Error("[eBPF] iter link attach error %s: %s\n", progName, err)
			continue
		}

		if pinIters {
			os.Remove(progPaths[progName])
			err = os.Mkdir(LiveDir, 0600)
			if err := iter.Pin(progPaths[progName]); err != nil {
				log.Error("[eBPF] pinning tasks error: %s\n", err)
			}
		}
		progHooks[progName] = iter
	}

	log.Debug("[eBPF] loaded\n")
}

// GetPidList dumps the tasks that are active in the kernel.
// The list can be read in /sys/fs/bpf/decloaker/tasks
// since kernel 5.9
func GetPidList(filterHost string) (taskList []Task) {
	iter, found := progHooks[ProgDumpTasks]
	if !found {
		log.Debug("iter %s not configured?\n", ProgDumpTasks)
		return taskList
	}
	iterReader, err := iter.Open()
	if err != nil {
		log.Error("iter.Open: %v\n", err)
		return taskList
	}
	defer iterReader.Close()

	tasks, err := io.ReadAll(iterReader)
	if err != nil {
		log.Error("%s not available\n", TasksPath)
		return taskList
	}
	if len(tasks) == 0 {
		log.Warn("[eBPF] kernel tasks empty (check previous errors).\n")
		return taskList
	}
	lines := strings.Split(string(tasks), "\n")
	for _, line := range lines {
		parts := reTasks.FindAllStringSubmatch(line, 1)
		if len(parts) == 0 || len(parts[0]) < 4 {
			continue
		}
		pid := parts[0][1]
		ppid := parts[0][2]
		// exclude threads
		if pid != ppid {
			continue
		}
		host := parts[0][6]
		if filterHost != "" && filterHost != host {
			continue
		}

		inode := parts[0][3]
		uid := parts[0][4]
		gid := parts[0][5]
		comm := utils.ToAscii(parts[0][7])
		exe := utils.ToAscii(parts[0][8])
		// index 0 is the string that matched
		taskList = append(taskList,
			[]Task{
				Task{
					Pid:      pid,
					PPid:     ppid,
					Inode:    inode,
					Uid:      uid,
					Gid:      gid,
					Hostname: host,
					Comm:     comm,
					Exe:      exe,
				},
			}...)
	}

	return taskList
}

func GetFileList(filterHost string) (fileList []File) {
	iter, found := progHooks[ProgDumpFiles]
	if !found {
		log.Debug("iter %s not configured?\n", ProgDumpFiles)
		return fileList
	}
	iterReader, err := iter.Open()
	if err != nil {
		log.Error("iter.Open: %v\n", err)
		return fileList
	}
	defer iterReader.Close()

	files, err := io.ReadAll(iterReader)
	if err != nil {
		log.Error("%s not available\n", FilesPath)
		return fileList
	}
	if len(files) == 0 {
		log.Warn("[eBPF] kernel tasks empty (check previous errors).\n")
		return fileList
	}
	lines := strings.Split(string(files), "\n")
	for _, line := range lines {
		parts := reFiles.FindAllStringSubmatch(line, 1)
		if len(parts) == 0 || len(parts[0]) < 7 {
			continue
		}
		pid := parts[0][1]
		ppid := parts[0][2]
		// exclude threads
		if pid != ppid {
			continue
		}
		host := parts[0][7]
		if filterHost != "" && filterHost != host {
			continue
		}

		fd := parts[0][3]
		inode := parts[0][4]
		uid := parts[0][5]
		gid := parts[0][6]
		file := utils.ToAscii(parts[0][8])
		comm := utils.ToAscii(parts[0][9])
		exe := utils.ToAscii(parts[0][10])
		// index 0 is the string that matched
		fileList = append(fileList,
			[]File{
				File{
					Pid:      pid,
					PPid:     ppid,
					Inode:    inode,
					Fd:       fd,
					Uid:      uid,
					Gid:      gid,
					Hostname: host,
					File:     file,
					Comm:     comm,
					Exe:      exe,
				},
			}...)
	}

	return fileList
}

// GetKmodList dumps the kernel modules that are active in the kernel.
// The list can be read in /sys/fs/bpf/decloaker/kmods
// since kernel 6.0
func GetKmodList() map[string]Kmod {
	kmodList := make(map[string]Kmod)

	iter, found := progHooks[ProgDumpKmods]
	if !found {
		log.Debug("iter %s not configured?\n", ProgDumpKmods)
		return kmodList
	}
	iterReader, err := iter.Open()
	if err != nil {
		log.Error("iter.Open: %v\n", err)
		return kmodList
	}
	defer iterReader.Close()

	kmods, err := io.ReadAll(iterReader)
	if err != nil {
		log.Error("%s not available\n", KmodsPath)
		return kmodList
	}

	if len(kmods) == 0 {
		log.Warn("[eBPF] kernel tasks empty (check previous errors).\n")
		return kmodList
	}
	lines := strings.Split(string(kmods), "\n")
	for _, line := range lines {
		parts := reKmods.FindAllStringSubmatch(line, 1)
		if len(parts) == 0 || len(parts[0]) < 5 {
			continue
		}
		atype := parts[0][2]
		kname := parts[0][4]
		if strings.HasPrefix(kname, "__builtin") && atype == "t" {
			log.Debug("excluding kmod %s:\n\t%v\n", kname, line)
			continue
		}
		// index 0 is the string that matched
		kmodList[parts[0][4]] = Kmod{
			Addr:  parts[0][1],
			AType: atype,
			Func:  parts[0][3],
			Name:  kname,
			Type:  parts[0][5],
		}
	}

	return kmodList
}

func CleanupIters() {
	for _, h := range progHooks {
		h.Close()
	}

	//os.Remove(TasksPath)
	//os.Remove(KmodsPath)
}
