package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/constants"
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

//go:embed kern/dump_netlink.o
var dumpNetlink []byte

//go:embed kern/dump_maps.o
var dumpMaps []byte

var (
	LiveDir     = "/sys/fs/bpf/decloaker"
	TasksPath   = "/sys/fs/bpf/decloaker/tasks"
	FilesPath   = "/sys/fs/bpf/decloaker/files"
	KmodsPath   = "/sys/fs/bpf/decloaker/kmods"
	NetlinkPath = "/sys/fs/bpf/decloaker/netlink"
	MapsPath    = "/sys/fs/bpf/decloaker/maps"
	reTasks     = regexp.MustCompile(`pid=([0-9]+)\sppid=([0-9]+)\sinode=([0-9]+)\suid=([0-9]+)\sgid=([0-9]+)\shost=([0-9A-Za-z_-]+)\scomm=(.{0,16})\sexe=(.*)$`)
	reFiles     = regexp.MustCompile(`pid=([0-9]+)\sppid=([0-9]+)\sfd=([0-9]+)\sinode=([0-9]+)\suid=([0-9]+)\sgid=([0-9]+)\shost=([0-9A-Za-z_-]+)\sfile=(.*)\scomm=(.{0,16})\sexe=(.*)$`)
	// addr=0xffffffffc4668010 atype=T func=hide_proc_modules_init name=lab_hide type=FTRACE_MOD 0x8000
	reKmods = regexp.MustCompile(`addr=([a-zA-Z0-9]+)\satype=([a-zA-Z0-9])\sfunc=([a-zA-Z0-9\-_]+)\sname=([a-zA-Z0-9\-_]+)\stype=([a-zA-Z0-9\-_]+)`)
	// pid=3753903271 proto=16  group=7864320  drops=0    dump=0    inode=9872
	reNetlink = regexp.MustCompile(`pid=([0-9]+)\sproto=([0-9])\sgroup=([0-9]+)\sdrops=([0-9]+)\sdump=([0-9]+)\sinode=([0-9]+)`)
	// vm_start=7f3805b38000 vm_end=7f3805b3b000 perms=r--p offset=00025000 dev=fd:02 inode=1582836 pid=2558411 ppid=2558411 comm=Web Content path=
	reMaps = regexp.MustCompile(`vm_start=([a-zA-Z0-9]+)\svm_end=([a-zA-Z0-9]+)\sperms=([-rwxp]+)\soffset=([a-z0-9]+)\sdev=([:a-z0-9]+)\sinode=([0-9]+)\sfile=(.*)\spid=([0-9]+)\sppid=([0-9]+)\shost=(.*)\scomm=(.{0,16})\spath=(.*)$`)

	ProgDumpTasks   = "dump_tasks"
	ProgDumpTasks5x = "dump_tasks"
	ProgDumpFiles   = "dump_files"
	ProgDumpKmods   = "dump_kmods"
	ProgDumpNetlink = "dump_netlink"
	ProgDumpMaps    = "dump_maps"

	progList = map[string][]byte{
		ProgDumpTasks:   dumpTask,
		ProgDumpFiles:   dumpFiles,
		ProgDumpKmods:   dumpKmod,
		ProgDumpNetlink: dumpNetlink,
		ProgDumpMaps:    dumpMaps,
	}
	progPaths = map[string]string{
		ProgDumpTasks:   TasksPath,
		ProgDumpFiles:   FilesPath,
		ProgDumpKmods:   KmodsPath,
		ProgDumpNetlink: NetlinkPath,
		ProgDumpMaps:    MapsPath,
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
	case constants.FieldExe:
		return t.Exe, true
	case constants.FieldCmdline:
		return t.Cmdline, true
	case constants.FieldPid:
		return t.Pid, true
	case constants.FieldPPid:
		return t.PPid, true
	case constants.FieldUid:
		return t.Uid, true
	case constants.FieldGid:
		return t.Gid, true
	case constants.FieldComm:
		return t.Comm, true
	case constants.FieldHostname:
		return t.Hostname, true
	case constants.FieldInode:
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
	case constants.FieldExe:
		return f.Exe, true
	case constants.FieldComm:
		return f.Comm, true
	case constants.FieldHostname:
		return f.Hostname, true
	case constants.FieldFile, constants.FieldPath:
		return f.File, true
	case constants.FieldUid:
		return f.Uid, true
	case constants.FieldGid:
		return f.Gid, true
	case constants.FieldInode:
		return f.Inode, true
	case constants.FieldFd:
		return f.Fd, true
	case constants.FieldPid:
		return f.Pid, true
	case constants.FieldPPid:
		return f.PPid, true
	}

	return nil, false
}

type Maps struct {
	VmStart  string
	VmEnd    string
	Perms    string
	Offset   string
	Dev      string
	Inode    string
	File     string
	Pid      string
	PPid     string
	Hostname string
	Comm     string
	Exe      string
}

func (m *Maps) Get(field string) (interface{}, bool) {
	switch field {
	case constants.FieldVmStart:
		return m.VmStart, true
	case constants.FieldVmEnd:
		return m.VmEnd, true
	case constants.FieldPerms:
		return m.Perms, true
	case constants.FieldOffset:
		return m.Offset, true
	case constants.FieldDev:
		return m.Dev, true
	case constants.FieldInode:
		return m.Inode, true
	case constants.FieldFile:
		return m.File, true
	case constants.FieldHostname:
		return m.Hostname, true
	case constants.FieldPid:
		return m.Pid, true
	case constants.FieldPPid:
		return m.PPid, true
	case constants.FieldExe:
		return m.Exe, true
	case constants.FieldComm:
		return m.Comm, true
	}

	return nil, false
}

type Netlink struct {
	Pid   string
	Proto string
	Group string
	Drops string
	Dump  string
	Inode string
	Exe   string
}

type Kmod struct {
	Addr  string
	AType string
	Func  string
	Name  string
	Type  string
}

type Filters struct {
	Pid      string
	PPid     string
	Inode    string
	Exe      string
	Hostname string
}

func loadIter(progName string, code []byte, filters *Filters) (*link.Iter, error) {
	collOpts := ebpf.CollectionOptions{}
	specs, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(code[:]))
	if err != nil {
		return nil, fmt.Errorf("module specs error %s: %s", progName, err)
	}
	log.Trace("[eBPF] %s global vars: %+v\n", progName, specs.Variables)

	if filters != nil {
		log.Debug("[eBPF] applying filters %+v\n", filters)
		iPid, _ := strconv.Atoi(filters.Pid)
		if iPid > 0 {
			specs.Variables["pid"].Set(uint32(iPid))
		}
		iPPid, _ := strconv.Atoi(filters.PPid)
		if iPPid > 0 {
			specs.Variables["ppid"].Set(uint32(iPPid))
		}
	}

	iterTask, err := ebpf.NewCollectionWithOptions(specs, collOpts)
	if iterTask == nil {
		return nil, fmt.Errorf("iter task %s: %s", progName, err)
	}
	prog := iterTask.Programs[progName]
	if prog == nil {
		return nil, fmt.Errorf("iter task nil %s: %s", progName, err)
	}

	iter, err := link.AttachIter(link.IterOptions{
		Program: prog,
	})
	if err != nil {
		log.Error("[eBPF] iter link attach error %s: %s\n", progName, err)
	}

	return iter, err
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

		iter, err := loadIter(progName, code, nil)

		if err != nil {
			log.Error("%s\n", err)
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

func ReloadTasksIter(pid, ppid string) {
	code := progList[ProgDumpTasks]
	iter, _ := loadIter(ProgDumpTasks, code, &Filters{Pid: pid, PPid: ppid})
	progHooks[ProgDumpTasks] = iter
}

func ReloadFilesIter(pid, ppid string) {
	code := progList[ProgDumpFiles]
	iter, _ := loadIter(ProgDumpFiles, code, &Filters{Pid: pid, PPid: ppid})
	progHooks[ProgDumpFiles] = iter
}

func ReloadMapsIter(pid, ppid string) {
	code := progList[ProgDumpMaps]
	iter, _ := loadIter(ProgDumpMaps, code, &Filters{Pid: pid, PPid: ppid})
	progHooks[ProgDumpMaps] = iter
}

// GetPidList dumps the tasks that are active in the kernel.
// The list can be read in /sys/fs/bpf/decloaker/tasks
// since kernel 5.9
func GetPidList(filters Filters) (taskList []Task) {
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
		if filters.Pid != "" && filters.Pid != pid {
			continue
		}
		if filters.PPid != "" && filters.PPid != ppid {
			continue
		}
		// exclude threads
		if pid != ppid {
			continue
		}

		inode := parts[0][3]
		if filters.Inode != "" && filters.Inode != inode {
			continue
		}

		host := parts[0][6]
		if filters.Hostname != "" && filters.Hostname != host {
			continue
		}

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

func GetFileList(filters Filters) (fileList []File) {
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
		if filters.Pid != "" && filters.Pid != pid {
			continue
		}
		if filters.PPid != "" && filters.PPid != ppid {
			continue
		}
		// exclude threads
		if pid != ppid {
			continue
		}

		host := parts[0][7]
		if filters.Hostname != "" && filters.Hostname != host {
			continue
		}

		fd := parts[0][3]
		inode := parts[0][4]
		if filters.Inode != "" && filters.Inode != inode {
			continue
		}

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

func GetNetlinkList(filters Filters) (nlkList []Netlink) {
	iter, found := progHooks[ProgDumpNetlink]
	if !found {
		log.Debug("iter %s not configured?\n", ProgDumpNetlink)
		return nlkList
	}
	iterReader, err := iter.Open()
	if err != nil {
		log.Error("iter.Open: %v\n", err)
		return nlkList
	}
	defer iterReader.Close()

	nlkLinks, err := io.ReadAll(iterReader)
	if err != nil {
		log.Error("%s not available\n", NetlinkPath)
		return nlkList
	}
	if len(nlkLinks) == 0 {
		log.Warn("[eBPF] netlink empty (check previous errors).\n")
		return nlkList
	}
	lines := strings.Split(string(nlkLinks), "\n")

	tasks := GetPidList(filters)

	for _, line := range lines {
		parts := reNetlink.FindAllStringSubmatch(line, 1)
		if len(parts) == 0 || len(parts[0]) < 5 {
			continue
		}
		// index 0 is the string that matched
		pid := parts[0][1]
		proto := parts[0][2]
		group := parts[0][3]
		drops := parts[0][4]
		dump := parts[0][5]
		inode := parts[0][6]

		if filters.Pid != "" && filters.Pid != pid {
			continue
		}
		if filters.Inode != "" && filters.Inode != inode {
			continue
		}

		exe := ""
		for _, t := range tasks {
			if t.Pid == pid {
				exe = t.Exe
			}
		}

		nlkList = append(nlkList,
			[]Netlink{
				Netlink{
					Pid:   pid,
					Proto: proto,
					Group: group,
					Drops: drops,
					Dump:  dump,
					Inode: inode,
					Exe:   exe,
				},
			}...)
	}

	return nlkList
}

func GetMapsList(filters Filters) (mapsList []Maps) {
	iter, found := progHooks[ProgDumpMaps]
	if !found {
		log.Debug("iter %s not configured?\n", ProgDumpMaps)
		return mapsList
	}
	iterReader, err := iter.Open()
	if err != nil {
		log.Error("iter.Open: %v\n", err)
		return mapsList
	}
	defer iterReader.Close()

	maps, err := io.ReadAll(iterReader)
	if err != nil {
		log.Error("%s not available\n", MapsPath)
		return mapsList
	}
	if len(maps) == 0 {
		log.Warn("[eBPF] kernel tasks empty (check previous errors).\n")
		return mapsList
	}
	lines := strings.Split(string(maps), "\n")
	for _, line := range lines {
		parts := reMaps.FindAllStringSubmatch(line, 1)
		if len(parts) == 0 || len(parts[0]) < 7 {
			continue
		}
		// index 0 is the string that matched
		vmstart := parts[0][1]
		vmend := parts[0][2]
		perms := parts[0][3]
		offset := parts[0][4]
		dev := parts[0][5]
		inode := parts[0][6]
		file := parts[0][7]
		pid := parts[0][8]
		ppid := parts[0][9]
		host := parts[0][10]
		comm := utils.ToAscii(parts[0][11])
		exe := utils.ToAscii(parts[0][12])

		if filters.Pid != "" && filters.Pid != pid {
			continue
		}
		if filters.PPid != "" && filters.PPid != ppid {
			continue
		}
		if filters.Hostname != "" && filters.Hostname != host {
			continue
		}
		if filters.Inode != "" && filters.Inode != inode {
			continue
		}

		mapsList = append(mapsList,
			[]Maps{
				Maps{
					VmStart: vmstart,
					VmEnd:   vmend,
					Perms:   perms,
					Offset:  offset,
					Dev:     dev,
					Inode:   inode,
					File:    file,
					Pid:     pid,
					PPid:    ppid,
					//Uid:      uid,
					//Gid:      gid,
					Hostname: host,
					Comm:     comm,
					Exe:      exe,
				},
			}...)
	}

	return mapsList
}

func CleanupIters() {
	for _, h := range progHooks {
		h.Close()
	}

	//os.Remove(TasksPath)
	//os.Remove(KmodsPath)
}
