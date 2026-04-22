/*   Copyright (C) 2025 Gustavo Iñiguez Goya
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
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/gustavo-iniguez-goya/decloaker/pkg"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/config"
	disk "github.com/gustavo-iniguez-goya/decloaker/pkg/disk"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/ebpf"
	dlog "github.com/gustavo-iniguez-goya/decloaker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/sys"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/utils"
	"github.com/gustavo-iniguez-goya/go-diskfs"
)

func main() {
	ctx := kong.Parse(&CLI,
		kong.Name("decloaker"),
		kong.Description("A generic malware unmasker"),
		kong.UsageOnError(),
	)

	dlog.NewLogger(CLI.Format)
	dlog.SetLogLevel(CLI.LogLevel)

	var ldLib = os.Getenv("LD_LIBRARY_PRELOAD")
	if ldLib != "" {
		dlog.Detection("\tWARNING!!\nLD_LIBRARY_PRELOAD env var found: %s\n", ldLib)
		dlog.Separator()
	}

	ebpf.ConfigureIters(CLI.PinKernelLists)

	var ret = decloaker.OK

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
		expected := disk.ReadDir(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Ls.Paths[0], diskfs.ReadOnly, CLI.Disk.Ls.Recursive)
		for file, stat := range expected {
			if stat == nil {
				continue
			}
			dlog.Log("%s\t%d\t%s\t%s\n",
				stat.Mode(),
				stat.Size(),
				stat.ModTime().Format(time.RFC3339),
				file)
		}

		if CLI.Disk.Ls.Compare {
			orig, _ := decloaker.ListFiles(CLI.Disk.Ls.Paths[0], sys.CmdFind, CLI.Disk.Ls.Recursive)
			ret = decloaker.CompareFiles(false, orig, expected)
		}
	case "disk cp <orig> <dest>":
		err := disk.Cp(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Cp.Orig, CLI.Disk.Cp.Dest, diskfs.ReadOnly)
		if err != nil {
			dlog.Error("%s\n", err)
			ret = decloaker.ERROR
		} else {
			dlog.Ok("OK\n")
		}
		// not implemented in go-diskfs
	case "disk mv <orig> <dest>":
		err := disk.Mv(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Cp.Orig, CLI.Disk.Cp.Dest, diskfs.ReadOnly)
		if err != nil {
			dlog.Error("%s\n", err)
			ret = decloaker.ERROR
		} else {
			dlog.Ok("OK\n")
		}
	case "disk stat <paths>":
		list, err := disk.Stat(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Stat.Paths, diskfs.ReadOnly)
		if err != nil {
			ret = decloaker.ERROR
			dlog.Error("%s\n", err)
		} else {
			for _, file := range list {
				dlog.Detection("%s\t%d\t%s\t%s\n", file.Mode(), file.Size(), file.ModTime().Format(time.RFC3339), file.Name())
				utils.PrintFileExtendedInfo(file.Sys())
			}
		}

	case "disk cat <path>":
		content, err := disk.ReadFile(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Cat.Path)
		if err != nil {
			dlog.Error("%s\n", err)
			ret = decloaker.ERROR
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

	case "disk rm <paths>":
		err := disk.Rm(CLI.Disk.Dev, CLI.Disk.Partition, CLI.Disk.Rm.Paths, diskfs.ReadWrite)
		if err != nil {
			dlog.Error("%s\n", err)
			ret = decloaker.ERROR
		} else {
			dlog.Ok("rm %v\n\n", CLI.Disk.Rm.Paths)
		}
	case "disk find <paths>":
		files := disk.Find(
			CLI.Disk.Dev,
			CLI.Disk.Partition,
			CLI.Disk.Find.Paths[0],
			CLI.Disk.Find.Inode,
			CLI.Disk.Find.Name,
			diskfs.ReadOnly,
			CLI.Disk.Find.Recursive,
		)
		for file, stat := range files {
			if stat == nil {
				continue
			}
			dlog.Log("%s\t%d\t%s\t%s\n",
				stat.Mode(),
				stat.Size(),
				stat.ModTime().Format(time.RFC3339),
				file)
		}

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
		ret = decloaker.CheckHiddenProcs(CLI.Scan.HiddenProcs.BruteForce, CLI.Scan.HiddenProcs.MaxPid)
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
		dlog.Detection("%-10s %-10s %-6s %-8s %-5s %-5s %s %-16s %s\t%s\n",
			"Pid", "PPid", "Fd", "Inode", "UID", "GID", "Host", "Comm", "File", "Exe")
		files := ebpf.GetFileList(CLI.Dump.Files.Host)
		for _, f := range files {
			dlog.Detection("%-10s %-10s %-6s %-8s %-5s %-5s %s %-16s %s\t%s\n",
				f.Pid, f.PPid,
				f.Fd, f.Inode,
				f.Uid, f.Gid,
				f.Hostname,
				f.Comm, f.File, f.Exe,
			)
		}
	case "dump kmods":
		dlog.Detection("%-20s\t%-10s\t%s\t%s\t%s\n",
			"Name", "Type", "Symbol", "Address", "Function")
		kmods := ebpf.GetKmodList()
		for _, k := range kmods {
			dlog.Detection("%-20s\t%-10s\t%s\t%s\t%s\n",
				k.Name,
				k.Type,
				k.AType,
				k.Addr,
				k.Func,
			)
		}
	case "dump tasks":
		dlog.Detection("%-10s %-10s %-8s %-8s %-8s %-16s %-16s %s\n",
			"Pid", "PPid", "Inode", "UID", "GID", "Host", "Comm", "Exe")
		tasks := ebpf.GetPidList(CLI.Dump.Tasks.Host)
		for _, t := range tasks {
			dlog.Detection("%-10s %-10s %-8s %-8s %-8s %-16s %-16s %s\n",
				t.Pid, t.PPid,
				t.Inode,
				t.Uid, t.Gid,
				t.Hostname,
				t.Comm, t.Exe,
			)
		}

	/* TODO
	case "config set":
		runConfigSet(CLI.Config.Set.Key, CLI.Config.Set.Value)
	case "config get":
		runConfigGet(CLI.Config.Get.Key)
	*/
	default:
		fmt.Println("No command specified, showing help:", ctx.Command())
		ctx.PrintUsage(true)
		ret = decloaker.ERROR
	}

	ebpf.CleanupIters()
	os.Exit(ret)
}

// =========================================================================

func scanHiddenFiles() int {
	if CLI.Scan.WithBuiltinPaths {
		paths := utils.ExpandPaths(decloaker.DefaultHiddenFilesPaths)
		CLI.Scan.HiddenFiles.Paths = append(CLI.Scan.HiddenFiles.Paths, paths...)
		CLI.Scan.HiddenFiles.Recursive = true
	}
	if len(CLI.Scan.HiddenFiles.Paths) == 0 {
		dlog.Error("no paths supplied\n")
		return 1
	}

	return decloaker.CheckHiddenFiles(CLI.Scan.HiddenFiles.Paths, CLI.Scan.HiddenFiles.Tool, CLI.Scan.HiddenFiles.Recursive)
}

func scanHiddenContent() int {
	if CLI.Scan.WithBuiltinPaths {
		paths := utils.ExpandPaths(decloaker.DefaultHiddenContentPaths)
		CLI.Scan.HiddenContent.Paths = append(CLI.Scan.HiddenContent.Paths, paths...)
	}
	if len(CLI.Scan.HiddenContent.Paths) == 0 {
		dlog.Error("no paths supplied")
		return 1
	}

	return decloaker.CheckHiddenContent(CLI.Scan.HiddenContent.Paths)
}

func scanSuspiciousProcs() int {
	dlog.Info("Looking for suspicious processes\n")
	cfg, err := config.New(CLI.Scan.SuspiciousProcs.Cfg)
	if err != nil {
		dlog.Warn("Invalid configuration: %s\n", err)
		return decloaker.OK
	}

	suspicious := decloaker.CheckSuspiciousProcs(cfg)
	if len(suspicious) == 0 {
		dlog.Info("no suspicious processes found\n\n")
		return decloaker.OK
	}
	for reason, t := range suspicious {
		dlog.Detection("%s\n\texe: %s\n\tcomm: %s\n\tcmdline: %s\n\thostname: %s\n\tUID: %s\n\tGID: %s\n\tPID: %s\n\tPPID: %s\n",
			reason,
			t.Exe, t.Comm, t.Cmdline, t.Hostname, t.Uid, t.Gid, t.Pid, t.PPid)
	}

	return decloaker.SUSPICIOUS_PROC
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
			dlog.Log("\n%s -------------------------\n", s.Proto)
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

/*func checkAll(paths []string, deep bool) {
}

func runConfigSet(key, value string) {
	fmt.Printf("Setting config: %s = %s\n", key, value)
	// TODO: Save config to file or DB
}

func runConfigGet(key string) {
	fmt.Printf("Retrieving config for key: %s\n", key)
	// TODO: Load config from file or DB
	fmt.Println("Value: <mocked-value>")
}*/
