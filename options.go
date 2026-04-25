package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"github.com/gustavo-iniguez-goya/decloaker/pkg"
)

type VersionFlag string

func (v VersionFlag) Decode(_ *kong.DecodeContext) error { return nil }
func (v VersionFlag) IsBool() bool                       { return true }
func (v VersionFlag) BeforeApply(app *kong.Kong, vars kong.Vars) error {
	fmt.Printf("decloaker - %s\n%s\n\n",
		decloaker.Version, decloaker.License)
	os.Exit(0)
	return nil
}

// CLI defines the full command structure.
var CLI struct {
	Version        VersionFlag `help:"Print version"`
	Format         string      `short:"f" help:"" global:""`
	LogLevel       string      `help:"log level (debug,info,warn,error,detection). Use detection to display only detections" default:"info" enum:"debug,info,warning,error,detection"`
	PinKernelLists bool        `help:"Make kernel lists permanent (kmods, pids, ...). They'll be available in /sys/fs/bpf/decloaker/tasks and /sys/fs/bpf/decloaker/kmods."`
	ConfigFile     string      `help:"configuration file" type:"path"`
	//Output  string `short:"o" help:"" global:""`
	//LogDate bool   `global:""`
	//LogTime bool   `global:""`
	//LogUTC  bool   `global:""`

	// https://github.com/alecthomas/kong?tab=readme-ov-file#supported-tags
	// https://github.com/alecthomas/kong?tab=readme-ov-file#custom-named-decoders

	// TODO
	//Log struct {
	//	Format string `arg:"" optional:"" name:"format" help:"Output format: plain, text, json (default plain)." type:"format"`
	//	Output string `arg:"" optional:"" name:"output" help:"Output file (default stdout)." type:"file"`
	//} `cmd:"" help:"Logging options." hidden:""`

	Cp struct {
		Orig string `arg:"" optional:"" name:"orig" help:"Source path" type:"path"`
		Dest string `arg:"" optional:"" name:"dest" help:"Dest path" type:"path"`
	} `cmd:"" help:"Copy file via syscalls."`
	Rm struct {
		Paths []string `arg:"" required:"" name:"paths" help:"Paths to delete." type:"path"`
	} `cmd:"" help:"Delete files via syscalls."`
	Ls struct {
		Paths            []string `arg:"" optional:"" name:"paths" help:"Paths to list." type:"path"`
		Recursive        bool     `short:"r" help:"Enable deep scanning."`
		ShowExtendedInfo bool     `help:"show extended information"`
	} `cmd:"" help:"List files via syscalls."`
	Mv struct {
		Orig string `arg:"" optional:"" name:"orig" help:"Source path" type:"path"`
		Dest string `arg:"" optional:"" name:"dest" help:"Dest path" type:"path"`
	} `cmd:"" help:"Move files via syscalls."`
	Cat struct {
		Paths []string `arg:"" optional:"" name:"paths" help:"Paths to cat." type:"path"`
	} `cmd:"" help:"Cat files via syscalls."`
	Stat struct {
		Paths []string `arg:"" help:"File path to stat." required:"" name:"paths" type:"path"`
	} `cmd:"" help:"Get details of a file or directory"`
	Netstat struct {
		Listen      bool `short:"l" help:"list sockets in Listen state"`
		Established bool `short:"e" help:"list established sockets"`
		// FIXME: this enum affects other commands?
		// enum:"tcp,udp,udplite,icmp,dccp,sctp,igmp,raw"
		Protos []string `arg:"" sep:"," enum:"tcp,tcp6,udp,udp6,udplite,udplite6,icmp,icmp6,dccp,dccp6,sctp,sctp6,igmp,igmp6,raw,raw6,packet" optional:"" name:"protos" help:"Protocols to dump (tcp, udp, xdp, raw, packet, icmp, sctp, igmp, dccp) Add 6 for ipv6 protocols (tcp6, udp6, ...)."`
		//Family []string `arg:"" optional:"" name:"family" help:"Families to dump (AF_INET, AF_XDP, ...)."`
	} `cmd:"" help:"List connections from kernel via netlink."`
	Conntrack struct {
		List struct {
		} `cmd:"" help:"Dump conntrack connections table from kernel."`
	} `cmd:"" help:"Manipulate conntrack connections table."`

	Disk struct {
		Dev       string `short:"d" help:"Disk device to read (/dev/sda1, ...)" required:"" name:"dev"`
		Partition int    `short:"p" help:"Device partition to read (0, 1, 5, ...)" name:"partition"`
		Ls        struct {
			Paths     []string `arg:"" help:"Paths to read." required:"" name:"paths"`
			Compare   bool     `short:"c" help:"Compare the output against system's ls output to detect hidden files."`
			Recursive bool     `short:"r" help:"Enable deep scanning."`
		} `cmd:"" help:"List directories and files by reading directly from the disk device"`
		Cp struct {
			Orig string `arg:"" help:"Origin file to copy." required:"" name:"orig"`
			Dest string `arg:"" help:"Destination file." required:"" name:"dest"`
		} `cmd:"" help:"Copy directories and files directly from the disk device"`
		// hidden, not implemented in go-disks yet.
		Mv struct {
			Orig string `arg:"" help:"Origin file to move or rename." required:"" name:"orig"`
			Dest string `arg:"" help:"Destination file." required:"" name:"dest"`
		} `cmd:"" help:"Rename files directly from the disk device" hidden:""`
		// hidden and dangerous, can cause filesystem errors
		Rm struct {
			Paths []string `arg:"" help:"Paths to delete. WARNING, DANGEROUS OPERATION, DO NOT USE" required:"" name:"paths"`
		} `cmd:"" help:"Delete files directly from the disk device" hidden:""`
		Stat struct {
			Paths []string `arg:"" help:"Paths to read." required:"" name:"paths"`
		} `cmd:"" help:"Return information about a path"`
		Cat struct {
			Path    string `arg:"" help:"File path to read." required:"" name:"path"`
			Compare bool   `short:"c" help:"Compare the output against system's cat ouput to detect hidden content."`
		} `cmd:"" help:"Reads the content of a file and prints it to stdout"`
		Find struct {
			Paths     []string `arg:"" help:"Paths to read." required:"" name:"paths"`
			Name      string   `short:"n" help:"Find files with this pattern."`
			Inode     uint64   `short:"i" help:"Look for this inode."`
			Recursive bool     `short:"r" default:"true" help:"Enable deep scanning."`
		} `cmd:"" help:"Find files in a disk device."`
	} `cmd:"" help:"Read files directly from the disk device."`

	Scan struct {
		WithBuiltinPaths bool `short:"w" optional:"" help:"Scan only important paths: /etc/ /usr/ /lib/ /tmp/, etc"`

		HiddenFiles struct {
			Paths     []string `arg:"" optional:"" help:"Paths to scan. Use /proc to analyze processes." name:"paths" type:"path"`
			Tool      string   `short:"t" optional:"" enum:"ls,find" default:"find" help:"System command to enumerate files and directories: ls, find."`
			Recursive bool     `short:"r" help:"Enable deep scanning."`
		} `cmd:"" help:"Look for hidden files, directories or processes (libc vs Go's std lib vs mmap)."`
		HiddenContent struct {
			Paths []string `arg:"" optional:"" help:"Paths to scan." name:"paths" type:"path"`
		} `cmd:"" help:"Open a file and check if it has hidden content (libc vs Go's std lib vs mmap)."`
		HiddenLkms struct {
		} `cmd:"" help:"Look for hidden kernel modules."`
		SuspiciousProcs struct {
			Cfg string `optional:"" help:"Configuration file" type:"file"`
		} `cmd:"" help:"Look for suspicious processes."`
		HiddenProcs struct {
			BruteForce bool `short:"b" help:"Try to find processes via brute force."`
			MaxPid     int  `short:"m" help:"Don't scan pass this pid."`
		} `cmd:"" help:"Look for hidden processes."`
		HiddenSockets struct {
			Protos []string `arg:"" sep:"," enum:"tcp,tcp6,udp,udp6,udplite,udplite6,icmp,icmp6,dccp,dccp6,sctp,sctp6,igmp,igmp6,raw,raw6,packet" optional:"" name:"protos" help:"Protocols to dump (tcp, udp, xdp, raw, packet, icmp, sctp, igmp, dccp) Add 6 for ipv6 protocols (tcp6, udp6, ...)."`
		} `cmd:"" help:"Look for hidden sockets."`

		// TODO
		System struct {
			//Paths     []string `arg:"" help:"Path to scan." required:"" name:"paths" type:"path"`
			//Recursive bool     `short:"r" help:"Enable deep scanning."`
		} `cmd:"" help:"scan the system looking for hidden procs, lkms, files or content."`
	} `cmd:"" help:"Commands to decloak files, directories or kernel modules."`

	Dump struct {
		Files struct {
			Host string `help:"Filter by hostname (container, pod, ...)" name:"host"`
		} `cmd:"" help:"Dump opened files."`
		Kmods struct {
		} `cmd:"" help:"Dump loaded kernel modules."`
		Tasks struct {
			Host string `help:"Filter by hostname (container, pod, ...)" name:"host"`
		} `cmd:"" help:"Dump running tasks (processes)."`
	} `cmd:"" help:"Commands to dump data from the kernel."`

	// TODO
	Config struct {
		Set struct {
			Key   string `arg:"" help:"Config key to set." required:""`
			Value string `arg:"" help:"Value to set." required:""`
		} `cmd:"" help:"Set a configuration value."`

		Get struct {
			Key string `arg:"" help:"Config key to get." required:""`
		} `cmd:"" help:"Get a configuration value."`
	} `cmd:"" help:"Configuration commands." hidden:""`
}
