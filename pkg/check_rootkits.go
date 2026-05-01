package decloaker

import (
	"bytes"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"

	"github.com/gustavo-iniguez-goya/decloaker/pkg/constants"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/ebpf"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/utils"
)

type taintT struct {
	letter string
	reason string
}

const (
	ProcKallsyms = "/proc/kallsyms"
	ProcModules  = "/proc/modules"
	SysModule    = "/sys/module/"
)

var (
	taint_values = map[int]taintT{
		0:  {"G/P", "proprietary module was loaded (G means all modules GPL; P means a proprietary module exists)"},
		1:  {"F", "module was force loaded (insmod -f)"},
		2:  {"S", "kernel running on an out-of-spec system / unsupported SMP/hardware configuration"},
		3:  {"R", "module was force unloaded (rmmod -f)"},
		4:  {"M", "processor reported a Machine Check Exception (MCE)"},
		5:  {"B", "bad page referenced / unexpected page flags (possible hardware or kernel bug)"},
		6:  {"U", "taint requested by userspace"},
		7:  {"D", "kernel has died recently (there was an OOPS or BUG)"},
		8:  {"A", "ACPI table overridden by user"},
		9:  {"W", "kernel issued warning"},
		10: {"C", "staging driver was loaded"},
		11: {"I", "workaround for bug in platform firmware applied"},
		12: {"O", "externally-built ('out-of-tree') module was loaded"},
		13: {"E", "unsigned module loaded on a kernel that supports module signatures"},
		14: {"L", "soft lockup occurred"},
		15: {"K", "kernel has been live patched"},
		16: {"X", "auxiliary taint, distro-defined"},
		17: {"T", "kernel built with randstruct plugin (set at build time)"},
		18: {"N", "an in-kernel test (e.g. KUnit) has been run"},
		19: {"J", "userspace used mutating debug op in fwctl (fwctl debug write)"},
	}

	// search for kmods under /sys/kernel/tracing/*
	reKmodBrckt = regexp.MustCompile(`\[([a-zA-Z0-9_-]+)\]`)
)

func CheckHiddenLKM() int {
	tainted := CheckTainted()
	retT := CheckTracingModules()
	retP := CheckProcModules(tainted)

	if retT != constants.OK || retP != constants.OK {
		return retT
	}
	log.Ok("no kernel modules hidden found\n")

	return constants.OK
}

func hiddenFromProc(procModules []byte, msg, kmod string) int {
	if !bytes.Contains(procModules, []byte(kmod)) {
		log.Event(log.DETECTION, log.CatHiddenKmod, msg,
			[]log.Fields{
				{Key: constants.FieldKmod, Value: kmod},
			})
		return constants.KMOD_HIDDEN
	}
	return constants.OK
}

func CheckTainted() bool {
	log.Info("Checking kernel integrity\n")

	tainted := false
	val, _ := os.ReadFile("/proc/sys/kernel/tainted")
	value, _ := strconv.Atoi(string(bytes.Trim(val, "\n")))
	if value == 0 {
		log.Ok("kernel not tainted\n")
		return tainted
	}

	log.Detection("\nWARNING: kernel tainted\n")
	for bit, t := range taint_values {
		mask := 1 << bit
		if value&mask != 0 {
			tainted = true
			log.Event(log.DETECTION, "kernel_taint", "\t(%s) %s\n",
				[]log.Fields{
					{Key: constants.FieldLetter, Value: t.letter},
					{Key: constants.FieldReason, Value: t.reason},
				})
		}
	}
	log.Log("\n")

	return tainted
}

// CheckProcModules verifies that all tainted modules exists in /proc/modules and /proc/kallsyms.
func CheckProcModules(tainted bool) int {
	log.Info("Checking loaded kernel modules\n")

	tainted_kmods := false
	ret := constants.OK
	kmodList := make(map[string]fs.DirEntry)
	procModules, _ := ioutil.ReadFile(ProcModules)
	procKallsyms, _ := ioutil.ReadFile(ProcKallsyms)
	ksymList := ebpf.GetKmodList()

	kmods, _ := os.ReadDir(SysModule)
	for _, k := range kmods {
		rktPath := SysModule + k.Name() + "/taint"
		log.Debug("checking kmod %s\n", rktPath)

		tainted, _ := os.ReadFile(rktPath)
		tainted = bytes.Trim(tainted, " \t\n")
		taintFlags := bytes.Trim(tainted, " \t\n")
		if bytes.Equal(taintFlags, []byte("")) {
			continue
		}
		tainted_kmods = true
		log.Event(log.DETECTION, "kernel_tainted", "tainted: %s, %s\n",
			[]log.Fields{
				{Key: constants.FieldKmod, Value: fmt.Sprintf("%s", k)},
				{Key: constants.FieldFlags, Value: fmt.Sprintf("%s", tainted)},
			})
		kmodList[k.Name()] = k

		hiddenFrom := []string{}
		if hiddenFromProc(procModules, "\n\tWARNING: \"%s\" kmod HIDDEN from /proc/modules\n", k.Name()) != constants.OK {
			hiddenFrom = append(hiddenFrom, ProcModules)
			ret = constants.KMOD_HIDDEN
		}
		if hiddenFromProc(procKallsyms, "\n\tWARNING: \"%s\" kmod HIDDEN from /proc/kallsyms\n", k.Name()) != constants.OK {
			hiddenFrom = append(hiddenFrom, ProcKallsyms)
			ret = constants.KMOD_HIDDEN
		}
		if len(hiddenFrom) > 0 {
			ret = constants.KMOD_HIDDEN
		}

	}

	for kname, kmod := range ksymList {
		if kmod.Type != "MOD" && kmod.Type != "FTRACE_MOD" {
			continue
		}

		hiddenFrom := []string{}
		if !utils.Exists(SysModule + kname) {
			log.Event(log.DETECTION, log.CatHiddenKmod, "\n\tWARNING (eBPF): \"%s\" kmod HIDDEN from /sys/module\n",
				[]log.Fields{
					{Key: constants.FieldKmod, Value: kname},
				})
			log.Log("\t%q\n", kmod)
			hiddenFrom = append(hiddenFrom, SysModule)
			ret = constants.KMOD_HIDDEN
		}
		if hiddenFromProc(procModules, "\n\tWARNING (eBPF): \"%s\" kmod HIDDEN from /proc/modules\n", kname) != constants.OK {
			log.Log("\t%q\n", kmod)
			hiddenFrom = append(hiddenFrom, ProcModules)
			ret = constants.KMOD_HIDDEN
		}
		if hiddenFromProc(procKallsyms, "\n\tWARNING (eBPF): \"%s\" kmod HIDDEN from /proc/kallsyms\n", kname) != constants.OK {
			hiddenFrom = append(hiddenFrom, ProcKallsyms)
			ret = constants.KMOD_HIDDEN
		}

		if len(hiddenFrom) > 0 {
			log.Log("\t%q\n", kmod)
			ret = constants.KMOD_HIDDEN
		}
	}

	if ret != constants.OK {
		log.Log("\n")
	}

	if tainted && !tainted_kmods {
		log.Detection("\n\tWARNING: the kernel is tainted, but we haven't found any kmod tainting the kernel. REVIEW\n\n")
	}

	return ret
}

// CheckTracingModules verifies that all modules hooking functions exists under /sys/modules/, /proc/modules and /proc/kallsyms.
func CheckTracingModules() int {
	log.Info("Checking kernel modules hooks\n")

	ret := constants.OK
	procModules, _ := ioutil.ReadFile(ProcModules)
	procKallsyms, _ := ioutil.ReadFile(ProcKallsyms)
	kmodList := make(map[string]struct{})

	monitorPaths := []string{
		"/sys/kernel/tracing/enabled_functions",
		"/sys/kernel/tracing/touched_functions",
	}

	for _, path := range monitorPaths {
		if !utils.Exists(path) {
			continue
		}
		log.Debug(" scanning %s\n", path)
		content, err := os.ReadFile(path)
		if err != nil {
			log.Error(" error reading %s: %s\n", path, err)
			continue
		}
		kmods := reKmodBrckt.FindAllStringSubmatch(string(content), -1)
		if len(kmods) == 0 {
			log.Debug(" no kmods found hooking functions in %s\n", path)
			continue
		}

		for _, k := range kmods {
			if _, found := kmodList[k[1]]; found {
				continue
			}
			log.Debug(" analyzing kmod: %s\n", k[1])

			log.Debug(" checking %s\n", ProcModules)
			hiddenFrom := []string{}
			if hiddenFromProc(procModules, "\tWARNING (tracing): possible kmod hidden from /proc/modules: %v\n", k[1]) != constants.OK {
				kmodList[k[1]] = struct{}{}
				hiddenFrom = append(hiddenFrom, ProcModules)
			}
			log.Debug(" checking %s\n", ProcKallsyms)
			if hiddenFromProc(procKallsyms, "\tWARNING (tracing): possible kmod hidden from /proc/kallsyms: %v\n", k[1]) != constants.OK {
				kmodList[k[1]] = struct{}{}
				hiddenFrom = append(hiddenFrom, ProcKallsyms)
			}
			log.Debug(" checking %s%s\n", SysModule, k[1])
			if !utils.Exists(SysModule + k[1]) {
				log.Event(log.DETECTION, log.CatHiddenKmod, "\tWARNING (tracing): possible kmod hidden from /sys/module: %v\n",
					[]log.Fields{
						{Key: constants.FieldKmod, Value: k[1]},
					})
				hiddenFrom = append(hiddenFrom, SysModule)
			}

			if len(hiddenFrom) > 0 {
				kmodList[k[1]] = struct{}{}
			}
		}
	}

	if len(kmodList) > 0 {
		log.Log("\n")
		ret = constants.KMOD_HIDDEN
	}

	return ret
}
