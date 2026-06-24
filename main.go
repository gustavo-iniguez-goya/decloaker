/*   Copyright (C) 2026 Gustavo Iñiguez Goya
//
//   This file is part of decloaker.
//
//   decloaker is free software: you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.
//
//   decloaker is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with decloaker.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/gustavo-iniguez-goya/decloaker/pkg"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/config"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/constants"
	disk "github.com/gustavo-iniguez-goya/decloaker/pkg/disk"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/ebpf"
	dlog "github.com/gustavo-iniguez-goya/decloaker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/sys"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/utils"
	"github.com/gustavo-iniguez-goya/go-diskfs"
)

var cfg *config.PatternsConfig

func main() {
	ctx := kong.Parse(&CLI,
		kong.Name("decloaker"),
		kong.Description("A generic malware unmasker"),
		kong.UsageOnError(),
	)

	dlog.NewLogger(CLI.Format)
	dlog.SetLogLevel(CLI.LogLevel)
	var err error
	cfg, err = config.New(CLI.ConfigFile)
	if err != nil {
		dlog.Warn("Error loading configuration, config file \"%s\"\n", CLI.ConfigFile)
	}

	var ldLib = os.Getenv("LD_LIBRARY_PRELOAD")
	if ldLib != "" {
		dlog.Detection("\tWARNING!!\nLD_LIBRARY_PRELOAD env var found: %s\n", ldLib)
		dlog.Separator()
	}

	ebpf.ConfigureIters(CLI.PinKernelLists)

	var ret = constants.OK

	switch ctx.Command() {
	//case "log <format> <output>":
	//	fmt.Printf("log format: %s, file: %s\n", CLI.Log.Format, CLI.Log.Output)
	case "cp <orig> <dest>":
		ret = decloaker.Copy(CLI.Cp.Orig, CLI.Cp.Dest)
	case "rm <paths>":
		ret = decloaker.Delete(CLI.Rm.Paths)
	case "ls <paths>":
		printLs(CLI.Ls.ShowExtendedInfo)
	case "mv <orig> <dest>":
		ret = decloaker.Rename(CLI.Mv.Orig, CLI.Mv.Dest)
	case "cat <paths>":
		ret = decloaker.Cat(CLI.Cat.Paths)
	case "stat <paths>":
		decloaker.PrintStat(CLI.Stat.Paths)

	case "netstat <protos>":
		printNetstat()
	case "netstat":
		printNetstat()

	case "conntrack list":
		decloaker.Conntrack()

	case "disk ls <paths>":
		ret = diskLs()
	case "disk cp <orig> <dest>":
		diskCp()
		// not implemented in go-diskfs
	case "disk mv <orig> <dest>":
		ret = diskMv()
	case "disk stat <paths>":
		ret = diskStat()
	case "disk cat <path>":
		ret = diskCat()
	case "disk rm <paths>":
		ret = diskRm()
	case "disk find <paths>":
		diskFind()

	case "scan hidden-files":
		ret = scanHiddenFiles()
	case "scan hidden-files <paths>":
		ret = scanHiddenFiles()
	case "scan hidden-content":
		ret = scanHiddenContent()
	case "scan hidden-content <paths>":
		ret = scanHiddenContent()
	case "scan hidden-lkms":
		ret = decloaker.CheckHiddenLKM()
	case "scan hidden-procs":
		ret = scanHiddenProcs()
	case "scan suspicious-procs":
		ret = scanSuspiciousProcs()
	case "scan hidden-sockets <protos>":
		ret = decloaker.CheckHiddenSockets(CLI.Scan.HiddenSockets.Protos)
	case "scan hidden-sockets":
		ret = decloaker.CheckHiddenSockets(CLI.Scan.HiddenSockets.Protos)
	case "scan system":
		CLI.Scan.WithBuiltinPaths = true
		CLI.Scan.HiddenFiles.Recursive = true
		scanHiddenFiles()
		scanHiddenContent()
		ret = decloaker.CheckHiddenLKM()
		ret = decloaker.CheckHiddenProcs(CLI.Scan.HiddenProcs.BruteForce, 0)

	case "dump files":
		dumpFiles()
	case "dump kmods":
		dumpKmods()
	case "dump tasks":
		dumpTasks()
	case "dump netlink":
		dumpNetlink()

	/* TODO
	case "config set":
		runConfigSet(CLI.Config.Set.Key, CLI.Config.Set.Value)
	case "config get":
		runConfigGet(CLI.Config.Get.Key)
	*/
	default:
		fmt.Println("No command specified, showing help:", ctx.Command())
		ctx.PrintUsage(true)
		ret = constants.ERROR
	}

	ebpf.CleanupIters()
	os.Exit(ret)
}

// =========================================================================

func getCliConfig(cliConfig string) *config.PatternsConfig {
	tmpCfg := *cfg
	if cliConfig == "" {
		return &tmpCfg
	}
	dlog.Info("Using config file %s\n", CLI.Scan.SuspiciousProcs.Cfg)
	_cfg, err := config.New(CLI.Scan.SuspiciousProcs.Cfg)
	if err != nil {
		dlog.Warn("Invalid configuration: %s\n", err)
	}
	tmpCfg = *_cfg
	return &tmpCfg
}

// =========================================================================

func scanHiddenFiles() int {
	if CLI.Scan.WithBuiltinPaths {
		paths := utils.ExpandPaths(constants.DefaultHiddenFilesPaths)
		if cfg != nil {
			paths = utils.ExpandPaths(cfg.Detection.DefaultHiddenPaths.Files)
		}
		CLI.Scan.HiddenFiles.Paths = append(CLI.Scan.HiddenFiles.Paths, paths...)
		CLI.Scan.HiddenFiles.Recursive = true
		dlog.Trace("Scanning for hidden files: %v\n", paths)
	}
	if len(CLI.Scan.HiddenFiles.Paths) == 0 {
		dlog.Error("no paths supplied\n")
		return 1
	}

	return decloaker.CheckHiddenFiles(CLI.Scan.HiddenFiles.Paths, CLI.Scan.HiddenFiles.Tool, CLI.Scan.HiddenFiles.Recursive)
}

func scanHiddenContent() int {
	if CLI.Scan.WithBuiltinPaths {
		paths := utils.ExpandPaths(constants.DefaultHiddenContentPaths)
		if cfg != nil {
			paths = utils.ExpandPaths(cfg.Detection.DefaultHiddenPaths.Content)
		}
		CLI.Scan.HiddenContent.Paths = append(CLI.Scan.HiddenContent.Paths, paths...)
		dlog.Trace("Scanning for hidden content: %v\n", paths)
	}
	if len(CLI.Scan.HiddenContent.Paths) == 0 {
		dlog.Error("no paths supplied")
		return 1
	}

	return decloaker.CheckHiddenContent(CLI.Scan.HiddenContent.Paths)
}

func scanHiddenProcs() int {
	ret := constants.OK
	if CLI.Scan.HiddenProcs.BindMount {
		ret = decloaker.CheckBindMounts()
		return ret
	}
	/*if CLI.Scan.HiddenProcs.Cgroups {
		ret = decloaker.CheckHiddenProcsCgroups(nil)
		return ret
	}*/
	ret = decloaker.CheckHiddenProcs(CLI.Scan.HiddenProcs.BruteForce, CLI.Scan.HiddenProcs.MaxPid)

	return ret
}

func scanSuspiciousProcs() int {
	dlog.Info("Looking for suspicious processes\n")
	cliCfg := getCliConfig(CLI.Scan.SuspiciousProcs.Cfg)
	if CLI.Scan.SuspiciousProcs.DumpPatterns {
		cfg.Dump()
		return constants.OK
	}

	suspicious := decloaker.CheckSuspiciousProcs(cliCfg)
	if len(suspicious) == 0 {
		dlog.Info("no suspicious processes found\n\n")
		return constants.OK
	}
	for reason, t := range suspicious {
		dlog.Event(dlog.DETECTION, dlog.CatHiddenPid, "%s\n\tmethod: %s\n\texe: %s\n\tcomm: %s\n\tcmdline: %s\n\thostname: %s\n\tUID: %s\n\tGID: %s\n\tPID: %s\n\tPPID: %s\n",
			[]dlog.Fields{
				{Key: constants.FieldReason, Value: reason},
				{Key: constants.FieldMethod, Value: decloaker.MethodPattern},
				{Key: constants.FieldExe, Value: t.Exe},
				{Key: constants.FieldComm, Value: strings.TrimRight(t.Comm, "\x00")},
				{Key: constants.FieldCmdline, Value: strings.TrimRight(string(t.Cmdline), "\x00")},
				{Key: constants.FieldHostname, Value: t.Hostname},
				{Key: constants.FieldUid, Value: t.Uid},
				{Key: constants.FieldGid, Value: t.Gid},
				{Key: constants.FieldPid, Value: t.Pid},
				{Key: constants.FieldPPid, Value: t.PPid},
			})
	}

	return constants.SUSPICIOUS_PROC
}

func printNetstat() {
	states := map[uint8]struct{}{}
	if CLI.Netstat.Listen {
		states[netlink.TCP_LISTEN] = struct{}{}
	}
	if CLI.Netstat.Established {
		states[netlink.TCP_ESTABLISHED] = struct{}{}
	}

	socketList := decloaker.Netstat(CLI.Netstat.Protos, states)

	dlog.Log("%-12s %-8s %-8s %-8s %6s:%-16s %16s:%-6s %-8s %-8s %-12s\n",
		"State", "Inode", "UID", "Ifname",
		"Sport", "Source", "Dst", "Dport",
		"PID", "PPID",
		"Host")

	lastProto := ""
	for _, s := range socketList {
		if lastProto == "" {
			lastProto = s.Proto
		}
		if lastProto != s.Proto {
			lastProto = s.Proto
			dlog.Info("\n%s -------------------------\n", s.Proto)
		}

		dlog.Log("%-12s %-8d %-8d %-8s %6d:%-16s %16s:%-6d %-8s %-8s %-12s\n\tcomm=%s exe=%s\n",
			strings.ToUpper(netlink.TCPStatesMap[s.Conn.State]),
			s.Conn.INode,
			s.Conn.UID,
			s.Ifname,
			s.Conn.ID.SourcePort,
			s.Conn.ID.Source,
			s.Conn.ID.Destination,
			s.Conn.ID.DestinationPort,
			s.Pid, s.Ppid,
			s.Host,
			s.Comm, s.Exe,
		)
		if cfg != nil {
			if match := cfg.MatchProcess(&s); match != nil {
				dlog.Detection("\nWARNING: %s\n\n", match.Description)
			}
		}
	}
	dlog.Log("\n")
}

func printLs(showExtendedInfo bool) {
	for _, p := range CLI.Ls.Paths {
		_, ls := decloaker.ListFiles(p, sys.CmdLs, CLI.Ls.Recursive)
		total := len(ls)
		for f, stat := range ls {
			if stat == nil {
				dlog.Info("%s (no stat info)\n", f)
				continue
			}
			dlog.Detection("%v\t%d\t%s\t%s\n", stat.Mode(), stat.Size(), stat.ModTime().Format(time.RFC3339), f)
			if showExtendedInfo {
				utils.PrintFileExtendedInfo(stat.Sys())
			}
		}
		dlog.Log("\n")
		dlog.Debug("%d files\n\n", total)
	}
}

func diskLs() int {
	ret := constants.OK

	callback := func(path string, stat os.FileInfo) {
		if stat == nil {
			dlog.Log("%s\t%d\t%s\t%s\n", "---------", 0, "",
				filepath.Base(path))
			return
		}
		owner := "- - -"
		uid := -1
		gid := -1
		inumber := -1
		ino := stat.Sys().(*syscall.Stat_t)
		if ino != nil {
			owner = fmt.Sprint(ino.Uid, " ", ino.Gid, " ", ino.Ino)
		}
		dlog.Log("%s\t%-4s\t%-6d\t%s\t%s\n",
			stat.Mode(),
			owner,
			stat.Size(),
			stat.ModTime().Format(time.RFC3339),
			filepath.Base(path))

		if !CLI.Disk.Ls.Compare {
			return
		}
		files := sys.Find("", []string{path, "-maxdepth", "0"}...)
		if _, found := files[path]; !found {
			dlog.Event(dlog.DETECTION, dlog.CatHiddenFile,
				"HIDDEN: %s  %d %d\t%d\t%d\t%s\t%s\n",
				[]dlog.Fields{
					{Key: constants.FieldMode, Value: fmt.Sprint(stat.Mode())},
					{Key: constants.FieldUid, Value: uid},
					{Key: constants.FieldGid, Value: gid},
					{Key: constants.FieldInode, Value: inumber},
					{Key: constants.FieldSize, Value: stat.Size()},
					{Key: constants.FieldTime, Value: stat.ModTime().Format(time.RFC822)},
					{Key: constants.FieldPath, Value: path},
				})
		}

	}
	disk.ReadDir(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Ls.Paths[0], diskfs.ReadOnly, CLI.Disk.Ls.Recursive, callback)

	return ret
}

func diskFind() {
	cb := func(path string, stat os.FileInfo) {
		if stat == nil {
			dlog.Log("%s\t%d\t%s\t%s\n", "---------", 0, "",
				path)
			return
		}
		owner := "- - -"
		uid := -1
		gid := -1
		inumber := -1
		ino := stat.Sys().(*syscall.Stat_t)
		if ino != nil {
			uid = int(ino.Uid)
			gid = int(ino.Gid)
			inumber = int(ino.Ino)
			owner = fmt.Sprint(ino.Uid, " ", ino.Gid, " ", ino.Ino)
		}
		dlog.Log("%s\t%s\t%d\t%s\t%s\n",
			stat.Mode(),
			owner,
			stat.Size(),
			stat.ModTime().Format(time.RFC3339),
			path)

		if !CLI.Disk.Find.Compare {
			return
		}
		files := sys.Find("", []string{path, "-maxdepth", "0"}...)
		if _, found := files[path]; !found {
			dlog.Event(dlog.DETECTION, dlog.CatHiddenFile,
				"HIDDEN: %s  %d %d\t%d\t%d\t%s\t%s\n",
				[]dlog.Fields{
					{Key: constants.FieldMode, Value: fmt.Sprint(stat.Mode())},
					{Key: constants.FieldUid, Value: uid},
					{Key: constants.FieldGid, Value: gid},
					{Key: constants.FieldInode, Value: inumber},
					{Key: constants.FieldSize, Value: stat.Size()},
					{Key: constants.FieldTime, Value: stat.ModTime().Format(time.RFC822)},
					{Key: constants.FieldPath, Value: path},
				})
		}
	}

	disk.Find(
		CLI.Disk.Dev,
		CLI.Disk.Partition,
		CLI.Disk.Find.Paths[0],
		CLI.Disk.Find.Inode,
		CLI.Disk.Find.Name,
		diskfs.ReadOnly,
		CLI.Disk.Find.Recursive,
		cb,
	)
}

func diskMv() int {
	ret := constants.OK

	err := disk.Mv(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Cp.Orig, CLI.Disk.Cp.Dest, diskfs.ReadOnly)
	if err != nil {
		dlog.Error("%s\n", err)
		ret = constants.ERROR
	} else {
		dlog.Ok("Ok\n")
	}

	return ret
}

func diskCat() int {
	ret := constants.OK
	content, err := disk.ReadFile(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Cat.Path)
	if err != nil {
		dlog.Error("%s\n", err)
		ret = constants.ERROR
	} else {
		dlog.Ok("cat %s:\n\n", CLI.Disk.Cat.Path)
		dlog.Detection("%s", content)
		dlog.Log("\n")

		if CLI.Disk.Cat.Compare {
			orig := sys.Cat("cat", CLI.Disk.Cat.Path)
			origSize := len(orig)
			ret = decloaker.CompareContent(CLI.Disk.Cat.Path, orig[CLI.Disk.Cat.Path], string(content), origSize, len(content), "raw")
		}
	}

	return ret
}

func diskRm() int {
	ret := constants.OK
	err := disk.Rm(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Rm.Paths, diskfs.ReadWrite)
	if err != nil {
		dlog.Error("%s\n", err)
		ret = constants.ERROR
	} else {
		dlog.Ok("rm %v\n\n", CLI.Disk.Rm.Paths)
	}

	return ret
}

func diskCp() int {
	ret := constants.OK
	err := disk.Cp(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Cp.Orig, CLI.Disk.Cp.Dest, CLI.Disk.Cp.Recursive, diskfs.ReadOnly)
	if err != nil {
		dlog.Error("%s\n", err)
		ret = constants.ERROR
	} else {
		dlog.Ok("Ok\n")
	}

	return ret
}

func diskStat() int {
	ret := constants.OK
	list, err := disk.Stat(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Stat.Paths, diskfs.ReadOnly)
	if err != nil {
		ret = constants.ERROR
		dlog.Error("%s\n", err)
	} else {
		for _, file := range list {
			dlog.Detection("%s\t%d\t%s\t%s\n", file.Mode(), file.Size(), file.ModTime().Format(time.RFC3339), file.Name())
			utils.PrintFileExtendedInfo(file.Sys())
		}
	}

	return ret
}

func dumpFiles() {
	ebpf.ReloadFilesIter(CLI.Dump.Files.PID, CLI.Dump.Files.PPID)

	dlog.Log("%-10s %-10s %-6s %-10s %-6s %-6s %s %-16s %s\t%s\n",
		"Pid", "PPid", "Fd", "Inode", "UID", "GID", "Hostname", "Comm", "File", "Exe")
	files := ebpf.GetFileList(CLI.Dump.Files.Host)
	for _, f := range files {
		dlog.Event(dlog.DETECTION, dlog.CatDumpFiles,
			"%-10s %-10s %-6s %-10s %-6s %-6s %s %-16s %s\t%s\n",
			[]dlog.Fields{
				{Key: constants.FieldPid, Value: f.Pid},
				{Key: constants.FieldPPid, Value: f.PPid},
				{Key: constants.FieldFd, Value: f.Fd},
				{Key: constants.FieldInode, Value: f.Inode},
				{Key: constants.FieldUid, Value: f.Uid},
				{Key: constants.FieldGid, Value: f.Gid},
				{Key: constants.FieldHostname, Value: f.Hostname},
				{Key: constants.FieldComm, Value: f.Comm},
				{Key: constants.FieldFile, Value: f.File},
				{Key: constants.FieldExe, Value: f.Exe},
			})
	}
}

func dumpKmods() {
	dlog.Log("%-20s\t%-10s\t%s\t%-18s\t%s\n",
		"Name", "Type", "Symbol", "Address", "Function")
	kmods := ebpf.GetKmodList()
	for _, k := range kmods {
		dlog.Event(dlog.DETECTION, dlog.CatDumpKmods, "%-20s\t%-10s\t%s\t%-18s\t%s\n",
			[]dlog.Fields{
				{Key: constants.FieldName, Value: k.Name},
				{Key: constants.FieldType, Value: k.Type},
				{Key: constants.FieldSymbol, Value: k.AType},
				{Key: constants.FieldAddr, Value: k.Addr},
				{Key: constants.FieldFunc, Value: k.Func},
			})
	}
}

func dumpTasks() {
	ebpf.ReloadTasksIter(CLI.Dump.Tasks.PID, CLI.Dump.Tasks.PPID)

	dlog.Log("%-10s %-10s %-10s %-8s %-8s %-16s %-16s %s\n",
		"Pid", "PPid", "Inode", "UID", "GID", "Host", "Comm", "Exe")
	tasks := ebpf.GetPidList(
		CLI.Dump.Tasks.Host,
		CLI.Dump.Tasks.PID,
		CLI.Dump.Tasks.PPID)
	for _, t := range tasks {
		dlog.Event(
			dlog.DETECTION,
			dlog.CatDumpTasks,
			"%-10s %-10s %-10s %-8s %-8s %-16s %-16s %s\n",
			[]dlog.Fields{
				{Key: constants.FieldPid, Value: t.Pid},
				{Key: constants.FieldPPid, Value: t.PPid},
				{Key: constants.FieldInode, Value: t.Inode},
				{Key: constants.FieldUid, Value: t.Uid},
				{Key: constants.FieldGid, Value: t.Gid},
				{Key: constants.FieldHostname, Value: t.Hostname},
				{Key: constants.FieldComm, Value: t.Comm},
				{Key: constants.FieldExe, Value: t.Exe},
			})
	}
}

func dumpNetlink() {
	dlog.Log("%-14s %-8s %-10s %-8s %-8s %-10s %s\n",
		"Pid", "Proto", "Group", "Drops", "Dump", "Inode", "Exe")
	tasks := ebpf.GetNetlinkList(CLI.Dump.Netlink.PID)
	for _, t := range tasks {
		dlog.Event(
			dlog.DETECTION,
			dlog.CatDumpNetlink,
			"%-14s %-8s %-10s %-8s %-8s %-10s %s\n",
			[]dlog.Fields{
				{Key: constants.FieldPid, Value: t.Pid},
				{Key: constants.FieldProto, Value: t.Proto},
				{Key: constants.FieldGroup, Value: t.Group},
				{Key: constants.FieldDrops, Value: t.Drops},
				{Key: constants.FieldDump, Value: t.Dump},
				{Key: constants.FieldInode, Value: t.Inode},
				{Key: constants.FieldExe, Value: t.Exe},
			})
	}
}
