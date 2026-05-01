package decloaker

import (
	"strconv"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/constants"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/sys"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/utils"
)

var procNetFiles = map[string]string{
	"tcp":      "/proc/net/tcp",
	"tcp6":     "/proc/net/tcp6",
	"udp":      "/proc/net/udp",
	"udp6":     "/proc/net/udp6",
	"udplite":  "/proc/net/udplite",
	"udplite6": "/proc/net/udplite6",
	"icmp":     "/proc/net/icmp",
	"icmp6":    "/proc/net/icmp6",
	"igmp":     "/proc/net/igmp",
	"igmp6":    "/proc/net/igmp6",
}

func CheckHiddenSockets(protos []string) int {
	hiddenConns := []Socket{}
	states := map[uint8]struct{}{}
	socketList := Netstat(protos, states)

	log.Log("%-12s %-8s %-8s %-8s %-6s %-16s %16s %-6s %-8s %-8s %-12s\n",
		"State", "Inode", "Uid", "IfnamE",
		"Sport", "Source", "Dst", "Dport",
		"Pid", "Ppid",
		"Host")

	for _, s := range socketList {
		if s.Exe == "" {
			var err error
			s.Exe, err = utils.ReadlinkEscaped("/proc/" + s.Pid + "/exe")
			if err != nil {
				s.Exe = "(unable to read process path, maybe a kernel thread)"
			}
		}

		log.Log("%-12s %-8d %-8d %-8s %-6d %-16s %16s %-6d %-8s %-8s %-12s\n\tcomm=%s exe=%s\n",
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

		procContent := ""
		if f, found := procNetFiles[s.Proto]; found {
			procTmp := sys.Cat("cat", f)
			procContent = procTmp[f]

			if strings.Index(procContent, strconv.Itoa(int(s.Conn.INode))) == -1 {
				hiddenConns = append(hiddenConns, s)
			}
		}
	}
	log.Log("\n")

	hiddenCount := len(hiddenConns)
	if hiddenCount == 0 {
		log.Info("No hidden sockets found.\n")
		return constants.OK
	}

	log.Detection("[!] %d HIDDEN connections found\n", hiddenCount)
	for _, s := range hiddenConns {
		log.Detection("%-12s %-8d %-8d %-8s %-6d %-16s %16s %-6d %-8s %-8s %-12s\n\tcomm=%s exe=%s\n",
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

	return constants.CONN_HIDDEN
}
