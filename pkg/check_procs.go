package decloaker

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	//"github.com/gustavo-iniguez-goya/decloaker/pkg/disk"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/config"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/constants"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/ebpf"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/sys"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/utils"
	"github.com/gustavo-iniguez-goya/taskstats"
)

const (
	// index of the fields of /proc/<pid>/status entries
	PidFieldName = 1
	PidName      = 0
	PidTGID      = 3
	PidPID       = 5
	PidPPID      = 6
	PidUID       = 8
	PidGID       = 9

	ProcPrefix = "/proc/"
	ProcMounts = "/proc/mounts"
	ProcPidMax = "/proc/sys/kernel/pid_max"

	MethodProc       = "proc"
	MethodStat       = "stat"
	MethodChdir      = "chdir"
	MethodBruteForce = "brute_force"
	MethodPattern    = "pattern"
	MethodEbpf       = "ebpf"
	MethodTaskStats  = "taskstats"
	MethodCgroup     = "cgroup"
	MethodBindMount  = "bind_mount"
)

var (
	reStatusField = regexp.MustCompile(`([A-Za-z]+):\t(.*)\n`)
)

func printHiddenPid(pid, ppid, inode, uid, gid, comm, exe string) {
	if exe == "" {
		exe, _ = utils.ReadlinkEscaped(ProcPrefix + pid + "/exe")
	}

	log.Event(log.DETECTION, log.CatHiddenPid, "WARNING (%s): pid hidden?\n\tPID: %s\tPPid: %s\n\tInode: %s\tUid: %s\tGid: %s\n\tComm: %s\n\tPath: %s\n\n",
		[]log.Fields{

			{Key: constants.FieldMethod, Value: MethodEbpf},
			{Key: constants.FieldPid, Value: pid},
			{Key: constants.FieldPPid, Value: ppid},
			{Key: constants.FieldInode, Value: inode},
			{Key: constants.FieldUid, Value: uid},
			{Key: constants.FieldGid, Value: gid},
			{Key: constants.FieldComm, Value: comm},
			{Key: constants.FieldExe, Value: utils.ToAscii(exe)},
		})
}

func getPidInfo(procPath string) ([][]string, string, error) {
	statusContent, err := os.ReadFile(procPath + "/status")
	if err != nil {
		return nil, "", err
	}
	status := reStatusField.FindAllStringSubmatch(string(statusContent), -1)
	var exe string
	exe, err = utils.ReadlinkEscaped(procPath + "/exe")
	if err != nil {
		exe = "(unable to read process path, maybe a kernel thread)"
	}
	if len(status) == 0 {
		err = fmt.Errorf("unable to read %s content", procPath)
	}

	return status, exe, nil
}

func printBinaryInfo(tgid, pid int) string {
	cmdline, _ := os.ReadFile(fmt.Sprint(ProcPrefix, pid, "/cmdline"))
	exe, _ := utils.ReadlinkEscaped(fmt.Sprint(ProcPrefix, pid, "/exe"))
	//hiddenProcs[tgid] = exe

	log.Event(log.DETECTION, log.CatHiddenPidThread, "WARNING: thread of a hidden PID found %d, ppid: %d\n\tPath: %s\n\tCmdline: %s\n\n",
		[]log.Fields{
			{Key: constants.FieldPid, Value: pid},
			{Key: constants.FieldTgid, Value: tgid},
			{Key: constants.FieldExe, Value: exe},
			{Key: constants.FieldCmdline, Value: strings.TrimRight(string(cmdline), "\x00")},
		})

	return exe
}

func checkOtherMethods(nlTasks *taskstats.Client, pid int) (string, int) {
	ret := constants.OK
	exe := ""
	procPath := fmt.Sprint(ProcPrefix, pid)

	statInf := Stat([]string{procPath})
	statWorked := len(statInf) > 0
	chdirWorked := os.Chdir(fmt.Sprint(ProcPrefix, pid)) == nil
	log.Trace("checkOtherMethods() stat: %v, chdir: %v\n", statWorked, chdirWorked)

	// point procPath to the exe. It may be overwritten by any of the following methods.
	procPath = fmt.Sprint(ProcPrefix, pid, "/exe")

	if nlTasks != nil {
		pidStats, _ := nlTasks.PID(pid)
		if pidStats != nil {
			log.Event(log.DETECTION, log.CatHiddenPid, "\tWARNING: hidden PID confirmed via %s: %d\n",
				[]log.Fields{
					{Key: constants.FieldMethod, Value: MethodTaskStats},
					{Key: constants.FieldPid, Value: pid},
				})
			ret = constants.PROC_HIDDEN
		}
	}
	if statWorked {
		log.Event(log.DETECTION, log.CatHiddenPid, "\tWARNING: hidden PID confirmed via %s: %d\n",
			[]log.Fields{
				{Key: constants.FieldMethod, Value: MethodStat},
				{Key: constants.FieldPid, Value: pid},
			})
		PrintStat([]string{procPath})
		ret = constants.PROC_HIDDEN
	}
	if chdirWorked {
		log.Event(log.DETECTION, log.CatHiddenPid, "\tWARNING: hidden PID confirmed via %s: %d\n",
			[]log.Fields{
				{Key: constants.FieldMethod, Value: MethodChdir},
				{Key: constants.FieldPid, Value: pid},
			})
		ret = constants.PROC_HIDDEN

		cwd, _ := os.Getwd()
		log.Trace("checkOtherMethods, cwd: %s\n", cwd)
		// we need to use relative paths if chdir worked
		procPath = "./exe"
	}

	statExe := Stat([]string{procPath})
	statExeWorked := len(statExe) > 0
	if statExeWorked && !statWorked {
		PrintStat([]string{procPath})
	}
	exe, _ = utils.ReadlinkEscaped(procPath)
	if exe != "" {
		log.Detection("\tPath: %s\n", exe)
	}
	if statExeWorked {
		log.Detection("\t(Binary path not found, use the inode to search it)\n")
	}

	return exe, ret
}

func bruteForcePids(nlTasks *taskstats.Client, expected map[string]os.FileInfo, maxPid int) int {
	ret := constants.OK

	hiddenProcs := make(map[int]string)
	pidMaxTmp, _ := os.ReadFile(ProcPidMax)
	pidMax, err := strconv.Atoi(string(bytes.Trim(pidMaxTmp, "\n")))
	if pidMax == 0 {
		log.Debug("/proc/sys/kernel/pid_max should not be 0 (error? %s)", err)
		pidMax = 4194304 // could be less
	}
	if maxPid > 0 {
		pidMax = maxPid
	}

	log.Info("trying with brute force (pid max: %d):\n", pidMax)

	procPath := ""
	for pid := 1; pid < pidMax; pid++ {
		procPath = fmt.Sprint(ProcPrefix, pid)
		if _, found := expected[procPath]; found || procPath == ourProcPath {
			continue
		}

		procPath = fmt.Sprint(ProcPrefix, pid, "/comm")
		comm, err := os.ReadFile(procPath)
		if err != nil {
			log.Trace("bruteForce() error reading %s, trying other methods\n", procPath)
			exe := ""
			exe, ret = checkOtherMethods(nlTasks, pid)
			hiddenProcs[pid] = exe
			continue
		}
		// this PID is hidden from filesystem tools. It could be a thread or a hidden PID.

		status, _, err := getPidInfo(fmt.Sprint(ProcPrefix, pid))
		if err != nil {
			log.Info("error %d: %s\n", pid, err)
			continue
		}

		// if it's a thread, check if the ppid is hidden
		if status[PidTGID][2] != status[PidPID][2] {
			tgid, _ := strconv.Atoi(status[PidTGID][2])
			if _, found := hiddenProcs[tgid]; !found {
				continue
			}
			exe := printBinaryInfo(tgid, pid)
			hiddenProcs[tgid] = exe
			continue
		}

		procPath = fmt.Sprint(ProcPrefix, pid, "/cmdline")
		cmdline, err := os.ReadFile(procPath)
		procPath = fmt.Sprint(ProcPrefix, pid, "/exe")
		exe, _ := utils.ReadlinkEscaped(procPath)
		hiddenProcs[pid] = exe

		log.Event(log.DETECTION, log.CatHiddenPid, "WARNING: found hidden proc? (%s) /proc/%d\n\n\texe: %s\n\tcomm: %s\n\tcmdline: %s\n\n",
			[]log.Fields{
				{Key: constants.FieldMethod, Value: MethodBruteForce},
				{Key: constants.FieldPid, Value: pid},
				{Key: constants.FieldExe, Value: exe},
				{Key: constants.FieldComm, Value: strings.TrimRight(string(bytes.Trim(comm, "\n")), "\x00")},
				{Key: constants.FieldCmdline, Value: strings.TrimRight(string(cmdline), "\x00")},
			})

		ret = constants.PROC_HIDDEN
	}

	if len(hiddenProcs) == 0 && ret == constants.OK {
		log.Info("No hidden processes found using brute force\n\n")
	}

	return ret
}

// CheckSuspiciousProcs returns a list of suspicious tasks and why they have been flagged.
func CheckSuspiciousProcs(cfg *config.PatternsConfig) map[string]ebpf.Task {
	ret := constants.OK
	suspicious := make(map[string]ebpf.Task)

	liveTasks := ebpf.GetPidList(ebpf.Filters{})
	if len(liveTasks) == 0 {
		log.Info("0 processes returned from kernel (is eBPF working? REVIEW)\n")
		return suspicious
	}

	for _, t := range liveTasks {
		ret = constants.OK
		status, bin, _ := getPidInfo(fmt.Sprint(ProcPrefix, t.Pid))

		msg := ""
		if t.Exe == "" {
			t.Exe = bin
		}

		cline, err := os.ReadFile(ProcPrefix + t.Pid + "/cmdline")
		if err != nil {
			log.Debug("CheckSuspiciousProcs, unable to read cmdline: %s, %s", t.Pid, t.Comm)
			continue
		}
		cmdline := string(cline)
		t.Cmdline = strings.Replace(cmdline, "\x00", " ", -1)
		log.Trace("analyzing process via eBPF: %v\n", t)

		// TODO:
		// - Allow to parse process tree.
		// - check for history=/dev/null in /proc/<pid>/environ
		// - check for uid, euid, gid, etc.

		if len(status) > 0 && strings.Compare(status[PidPPID][1], "2") == 0 {
			msg = fmt.Sprintf("\t\nWARNING (%s): ppid == 2?\n", t.Pid)
			ret = constants.SUSPICIOUS_PROC
		}

		if match := cfg.MatchProcess(&t); match != nil {
			msg += fmt.Sprintf("\t\nWARNING (%s): %s\n", t.Pid, match.Description)
			ret = constants.SUSPICIOUS_PROC
		}
		if ret == constants.SUSPICIOUS_PROC {
			suspicious[msg] = t
		}
	}

	liveMaps := ebpf.GetMapsList(ebpf.Filters{})
	for _, t := range liveMaps {
		if match := cfg.MatchFile(&t); match != nil {
			log.Info("\t\nWARNING (%s): %s\n", t.Pid, match.Description)
			ret = constants.SUSPICIOUS_PROC
		}
	}

	return suspicious
}

// CheckBindMounts looks for PIDs hidden with bind mounts.
func CheckBindMounts() int {
	ret := constants.OK
	printPid := func(procPathB []byte) {
		procPath := string(procPathB)
		status, exe, err := getPidInfo(procPath)
		if err != nil {
			return
		}
		// Log the overlay (visible) PID first.
		log.Event(log.DETECTION, log.CatHiddenPidMount, "\tOverlay PID (%s):\n\t  PID: %s\n\t  PPid: %s\n\t  Comm: %s\n\t  Path: %s\nMount path: %s\n\n",
			[]log.Fields{
				{Key: constants.FieldMethod, Value: MethodBindMount},
				{Key: constants.FieldPid, Value: status[PidPID][2]},
				{Key: constants.FieldPPid, Value: status[PidPPID][2]},
				{Key: constants.FieldComm, Value: status[PidName][2]},
				{Key: constants.FieldExe, Value: exe},
				{Key: constants.FieldMountPath, Value: procPath},
			})

		err = exec.Command("umount", procPath).Run()
		if err != nil {
			log.Error("unable to umount %s to unhide the PID\n", procPath)
			return
		}
		log.Debug("%s umounted\n", procPath)

		status, exe, err = getPidInfo(procPath)
		// Log the now-revealed hidden PID.
		log.Event(log.DETECTION, log.CatHiddenPidMount, "\tHIDDEN PID (%s):\n\t  PID: %s\n\t  PPid: %s\n\t  Comm: %s\n\t  Path: %s\nMount path: %s\n\n",
			[]log.Fields{
				{Key: constants.FieldMethod, Value: MethodBindMount},
				{Key: constants.FieldPid, Value: status[PidPID][2]},
				{Key: constants.FieldPPid, Value: status[PidPPID][2]},
				{Key: constants.FieldComm, Value: status[PidName][2]},
				{Key: constants.FieldExe, Value: exe},
				{Key: constants.FieldMountPath, Value: procPath},
			})
	}

	mounts, err := os.ReadFile(ProcMounts)
	if err != nil {
		log.Error("mounted pid: %s", err)
	} else {
		mountsRe := regexp.MustCompile(`\/proc\/[0-9]+`)
		if matches := mountsRe.FindAll(mounts, -1); matches != nil {
			ret = constants.PID_BIND_MOUNT
			for n, m := range matches {
				log.Detection("%d - WARNING, pid hidden under another pid (mount): %s\n", n, m)
				printPid(m)
			}
			log.Log("\n")
		}
	}

	return ret
}

func CheckHiddenProcsCgroups(nlTasks *taskstats.Client, expected map[string]os.FileInfo) int {
	log.Info("Checking hidden processes via cgroups:\n\n")
	ret := constants.OK
	if nlTasks == nil {
		nlTasks, _ = taskstats.New()
	}

	cgroups := ReadDir("/sys/fs/cgroup/", true)
	for path := range cgroups {
		base := filepath.Base(path)
		if len(base) > 6 && base[len(base)-6:] != ".procs" {
			continue
		}
		if len(base) > 8 && base[len(base)-8:] != ".threads" {
			continue
		}
		log.Trace("checking cgroup path %s", path)
		cgs, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		pidList := string(cgs)
		for _, pid := range strings.Split(pidList, "\n") {
			if pid == "" || pid == ourPid {
				continue
			}
			cgPid := fmt.Sprint(ProcPrefix, pid)
			if _, found := expected[cgPid]; found {
				continue
			}
			iPid, _ := strconv.Atoi(pid)
			checkOtherMethods(nlTasks, iPid)
			ret = constants.PROC_HIDDEN

			fields := []log.Fields{
				{Key: constants.FieldMethod, Value: MethodCgroup},
				{Key: constants.FieldPid, Value: pid},
				{Key: constants.FieldCgroupPath, Value: path},
			}
			log.Event(
				log.DETECTION,
				log.CatHiddenCgroup,
				"WARNING: hidden PID found via %s, PID: %d, Cgroup path: %s\n",
				fields)

			// Enrich with taskstats if available.
			if nlTasks == nil {
				log.Debug("unable to obtain PID info via TaskStats\n")
				continue
			}
			spid, _ := strconv.Atoi(pid)
			pidStats, _ := nlTasks.PID(spid)
			if pidStats != nil {
				comm := utils.IntSliceToString(pidStats.Comm, "")
				fields = []log.Fields{
					{Key: constants.FieldMethod, Value: MethodTaskStats},
					{Key: constants.FieldComm, Value: comm},
					{Key: constants.FieldPPid, Value: pidStats.PPID},
					{Key: constants.FieldTgid, Value: pidStats.TGID},
					{Key: constants.FieldUid, Value: pidStats.UID},
					{Key: constants.FieldGid, Value: pidStats.GID},
					{Key: constants.FieldExeDev, Value: pidStats.ExeDev},
					{Key: constants.FieldInode, Value: pidStats.ExeInode},
				}
				log.Event(
					log.DETECTION,
					log.CatHiddenCgroupTaskStats,
					"\t%s info:\n\tComm: %s, PPID: %d, TGID: %d, UID: %d, GID: %d, Dev: %d, Inode: %d\n",
					fields)
			} else {
				log.Error("pidStats nil, unable to obtain pid info (%d)\n", pid)
			}
		}
	}

	return ret
}

func CheckHiddenProcs(doBruteForce bool, maxPid int) int {
	log.Info("Checking hidden processes:\n\n")

	nlTasks, _ := taskstats.New()
	ret := constants.OK
	retBrute := constants.OK
	retBind := CheckBindMounts()

	orig, expected := ListFiles("/proc", sys.CmdLs, false)
	ret = CompareFiles(true, orig, expected)

	liveTasks := ebpf.GetPidList(ebpf.Filters{})
	for _, t := range liveTasks {
		procPath := ProcPrefix + t.Pid
		if procPath == ourProcPath {
			continue
		}

		if _, found := orig[procPath]; found {
			continue
		}

		printHiddenPid(t.Pid, t.PPid, t.Inode, t.Uid, t.Gid, t.Comm, t.Exe)

		statInf := Stat([]string{procPath})
		if len(statInf) > 0 {
			log.Event(log.DETECTION, log.CatHiddenPid, "hidden PID confirmed via %s (eBPF): %s, %s\n\n",
				[]log.Fields{
					{Key: constants.FieldMethod, Value: MethodStat},
					{Key: constants.FieldPid, Value: t.Pid},
					{Key: constants.FieldComm, Value: t.Comm},
				})
			PrintStat([]string{procPath})
		}
		ret = constants.PROC_HIDDEN
	}

	if len(liveTasks) == 0 {
		ret = CheckHiddenProcsCgroups(nlTasks, expected)
	}

	if doBruteForce {
		retBrute = bruteForcePids(nlTasks, expected, maxPid)
	}

	if ret != constants.OK || retBind != constants.OK || retBrute != constants.OK {
		log.Warn("hidden processes found.\n\n")
		if retBind != constants.OK {
			ret = retBind
		}
		if retBrute != constants.OK {
			ret = retBrute
		}
	}
	if ret == constants.OK {
		log.Info("No hidden processes found. You can try it with \"decloaker scan hidden-procs --brute-force\"\n\n")
	}

	return ret
}
