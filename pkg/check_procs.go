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
)

var (
	reStatusField = regexp.MustCompile(`([A-Za-z]+):\t(.*)\n`)
)

func printHiddenPid(pid, ppid, inode, uid, gid, comm, exe string) {

	if exe == "" {
		exe, _ = utils.ReadlinkEscaped(ProcPrefix + pid + "/exe")
	}

	log.Detection("\tPID: %s\tPPid: %s\n\tInode: %s\tUid: %s\tGid: %s\n\tComm: %s\n\tPath: %s\n\n",
		pid,
		ppid,
		inode,
		uid,
		gid,
		comm,
		utils.ToAscii(exe),
	)
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
	log.Detection("WARNING: thread of a hidden PID found %d, ppid: %d\n", pid, tgid)
	cmdline, _ := os.ReadFile(fmt.Sprint(ProcPrefix, pid, "/cmdline"))
	exe, _ := utils.ReadlinkEscaped(fmt.Sprint(ProcPrefix, pid, "/exe"))
	//hiddenProcs[tgid] = exe

	log.Detection("\tPath: %s\n\tCmdline: %s\n\n", exe, cmdline)

	return exe
}

func checkOtherMethods(nlTasks *taskstats.Client, pid int) (string, int) {
	ret := OK
	exe := ""
	procPath := fmt.Sprint(ProcPrefix, pid)

	statInf := Stat([]string{procPath})
	statWorked := len(statInf) > 0
	chdirWorked := os.Chdir(fmt.Sprint(ProcPrefix, pid)) == nil
	if nlTasks != nil {
		pidStats, _ := nlTasks.PID(pid)
		if pidStats != nil {
			log.Detection("\tWARNING: hidden PID confirmed via TaskStats: %d\n", pid)
			ret = PROC_HIDDEN
		}
	} else if statWorked {
		log.Detection("\tWARNING: hidden PID confirmed via Stat: %d\n", pid)
		PrintStat([]string{procPath})
		ret = PROC_HIDDEN
	} else if chdirWorked {
		log.Detection("\tWARNING: hidden PID confirmed via Chdir: %d\n", pid)
		ret = PROC_HIDDEN
	}

	procPath = fmt.Sprint(ProcPrefix, pid, "/exe")
	statExe := Stat([]string{procPath})
	statExeWorked := len(statExe) > 0
	if statExeWorked {
		PrintStat([]string{procPath})
	}
	exe, _ = utils.ReadlinkEscaped(procPath)
	if exe != "" {
		log.Detection("\tPath: %s\n", exe)
	} else if statExeWorked {
		log.Detection("\t(Binary path not found, use the inode to search it)\n")
	}

	return exe, ret
}

func bruteForcePids(nlTasks *taskstats.Client, expected map[string]os.FileInfo, maxPid int) int {
	ret := OK

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

		log.Detection("WARNING: hidden proc? /proc/%d\n", pid)
		log.Detection("\n\texe: %s\n\tcomm: %s\n\tcmdline: %s\n\n", exe, bytes.Trim(comm, "\n"), cmdline)

		ret = PROC_HIDDEN
	}

	if len(hiddenProcs) == 0 && ret == OK {
		log.Info("No hidden processes found using brute force\n\n")
	}

	return ret
}

// CheckSuspiciousProcs returns a list of suspicious tasks and why they have been flagged.
func CheckSuspiciousProcs(cfg *config.PatternsConfig) map[string]ebpf.Task {
	ret := OK
	suspicious := make(map[string]ebpf.Task)

	liveTasks := ebpf.GetPidList("")
	for _, t := range liveTasks {
		ret = OK
		status, bin, _ := getPidInfo(fmt.Sprint(ProcPrefix, t.Pid))

		msg := ""
		exe := ""
		if t.Exe != "" {
			exe = t.Exe
		} else {
			exe = bin
		}

		cline, err := os.ReadFile(ProcPrefix + t.Pid + "/cmdline")
		if err != nil {
			log.Debug("CheckSuspiciousProcs, unable to read cmdline: %s, %s", t.Pid, t.Comm)
			continue
		}
		cmdline := string(cline)
		t.Cmdline = cmdline

		// TODO:
		// - Allow to parse process tree.
		// - check for history=/dev/null in /proc/<pid>/environ

		if len(status) > 0 && strings.Compare(status[PidPPID][1], "2") == 0 {
			msg = fmt.Sprintf("\t\nWARNING (%s): ppid == 2?\n", t.Pid)
			ret = SUSPICIOUS_PROC
		}

		if match := cfg.MatchProcess(&t); match != nil {
			msg += fmt.Sprintf("\t\nWARNING (%s): %s\n", t.Pid, match.Description)
			ret = SUSPICIOUS_PROC
		}
		if ret == SUSPICIOUS_PROC {
			suspicious[msg] = t
		}
	}

	return suspicious
}

// CheckBindMounts looks for PIDs hidden with bind mounts.
func CheckBindMounts() int {
	ret := OK
	printPid := func(procPathB []byte) {
		procPath := string(procPathB)
		status, exe, err := getPidInfo(procPath)
		if err != nil {
			return
		}
		log.Detection("\tOverlay PID:\n\t  PID: %s\n\t  PPid: %s\n\t  Comm: %s\n\t  Path: %s\n\n",
			status[PidPID][2],
			status[PidPPID][2],
			status[PidName][2],
			exe,
		)

		err = exec.Command("umount", procPath).Run()
		if err != nil {
			log.Error("unable to umount %s to unhide the PID\n", procPath)
			return
		}
		log.Debug("%s umounted\n", procPath)

		status, exe, err = getPidInfo(procPath)
		log.Detection("\tHIDDEN PID:\n\t  PID: %s\n\t  PPid: %s\n\t  Comm: %s\n\t  Path: %s\n\n",
			status[PidPID][2],
			status[PidPPID][2],
			status[PidName][2],
			exe,
		)
	}

	mounts, err := os.ReadFile(ProcMounts)
	if err != nil {
		log.Error("mounted pid: %s", err)
	} else {
		mountsRe := regexp.MustCompile(`\/proc\/[0-9]+`)
		if matches := mountsRe.FindAll(mounts, -1); matches != nil {
			ret = PID_BIND_MOUNT
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
	ret := OK

	cgroups := ReadDir("/sys/fs/cgroup/", true)
	for path := range cgroups {
		base := filepath.Base(path)
		if len(base) > 6 && base[len(base)-6:] != ".procs" {
			continue
		}
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
			log.Log("WARNING: hidden PID found via Cgroups: %s\n", cgPid)
			checkOtherMethods(nlTasks, iPid)
			ret = PROC_HIDDEN

			// TODO: https://github.com/mdlayher/taskstats/issues/14
			if nlTasks == nil {
				log.Debug("unable to obtain PID info via TaskStats\n")
				continue
			}
			spid, _ := strconv.Atoi(pid)
			pidStats, _ := nlTasks.PID(spid)
			comm := utils.IntSliceToString(pidStats.Comm, "")
			log.Log("\tComm: %s\n\tPID: %d, PPID: %d, TGID: %d, UID: %d, GID: %d, Dev: %d, Inode: %d\n",
				comm,
				pidStats.PID,
				pidStats.PPID,
				pidStats.TGID,
				pidStats.UID,
				pidStats.GID,
				pidStats.ExeDev,
				pidStats.ExeInode,
			)
		}
	}

	return ret
}

func CheckHiddenProcs(doBruteForce bool, maxPid int) int {
	log.Info("Checking hidden processes:\n\n")

	nlTasks, _ := taskstats.New()
	ret := OK
	retBrute := OK
	retBind := CheckBindMounts()

	orig, expected := ListFiles("/proc", sys.CmdLs, false)
	ret = CompareFiles(true, orig, expected)

	liveTasks := ebpf.GetPidList("")
	for _, t := range liveTasks {
		procPath := ProcPrefix + t.Pid
		if procPath == ourProcPath {
			continue
		}

		if _, found := orig[procPath]; found {
			continue
		}

		log.Detection("WARNING (ebpf): pid hidden?\n")

		printHiddenPid(t.Pid, t.PPid, t.Inode, t.Uid, t.Gid, t.Comm, t.Exe)
		statInf := Stat([]string{procPath})
		if len(statInf) > 0 {
			log.Detection("\tPID confirmed via Stat: %s, %s\n\n", t.Pid, t.Comm)
			PrintStat([]string{procPath})
		}
		ret = PROC_HIDDEN
	}

	if len(liveTasks) == 0 {
		ret = CheckHiddenProcsCgroups(nlTasks, expected)
	}

	if doBruteForce {
		retBrute = bruteForcePids(nlTasks, expected, maxPid)
	}

	if ret != OK || retBind != OK || retBrute != OK {
		log.Warn("hidden processes found.\n\n")
		if retBind != OK {
			ret = retBind
		}
		if retBrute != OK {
			ret = retBrute
		}
	}
	if ret == OK {
		log.Info("No hidden processes found. You can try it with \"decloaker scan hidden-procs --brute-force\"\n\n")
	}

	return ret
}
