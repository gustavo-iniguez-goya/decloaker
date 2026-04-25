package decloaker

import (
	"golang.org/x/sys/unix"
	"net"
	"strconv"
	"syscall"

	"github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/ebpf"
	"github.com/gustavo-iniguez-goya/decloaker/pkg/log"

	ntl "github.com/vishvananda/netlink"
)

// functions to dump the connections from the kernel, instead of parsing /proc/net/*

type Socket struct {
	Conn   *netlink.Socket
	Proto  string
	Exe    string
	Comm   string
	Host   string
	Ifname string
	Ppid   string
	Pid    string
}

func (s *Socket) Get(field string) (interface{}, bool) {
	switch field {
	case "exe":
		return s.Exe, true
	case "comm":
		return s.Comm, true
	case "pid":
		return s.Pid, true
	case "ppid":
		return s.Ppid, true
	case "uid":
		return s.Conn.UID, true
	case "hostname":
		return s.Host, true
	case "ifname":
		return s.Ifname, true
	case "inode":
		return s.Conn.INode, true
	case "src_port":
		return s.Conn.ID.SourcePort, true
	case "dst_port":
		return s.Conn.ID.DestinationPort, true
	case "src_ip":
		return s.Conn.ID.Source, true
	case "dst_ip":
		return s.Conn.ID.Destination, true
		//case "maps":
		//    return t.Maps, true
		//case "environ":
		//    return t.Environ, true
	}
	return nil, false
}

type Protos struct {
	Proto uint8
	Fam   uint8
}

var knownFams = map[string]uint8{
	"af_inet":   syscall.AF_INET,
	"af_inet6":  syscall.AF_INET6,
	"af_packet": syscall.AF_PACKET,
}

var (
	knownProtos = map[string]Protos{
		"tcp":      Protos{syscall.IPPROTO_TCP, syscall.AF_INET},
		"tcp6":     Protos{syscall.IPPROTO_TCP, syscall.AF_INET6},
		"udp":      Protos{syscall.IPPROTO_UDP, syscall.AF_INET},
		"udp6":     Protos{syscall.IPPROTO_UDP, syscall.AF_INET6},
		"udp-raw":  Protos{syscall.IPPROTO_UDP, syscall.AF_PACKET},
		"icmp":     Protos{syscall.IPPROTO_ICMP, syscall.AF_INET},
		"icmp6":    Protos{syscall.IPPROTO_ICMP, syscall.AF_INET6},
		"udplite":  Protos{syscall.IPPROTO_UDPLITE, syscall.AF_INET},
		"udplite6": Protos{syscall.IPPROTO_UDPLITE, syscall.AF_INET6},
		"dccp":     Protos{syscall.IPPROTO_DCCP, syscall.AF_INET},
		"dccp6":    Protos{syscall.IPPROTO_DCCP, syscall.AF_INET6},
		"sctp":     Protos{syscall.IPPROTO_SCTP, syscall.AF_INET},
		"sctp6":    Protos{syscall.IPPROTO_SCTP, syscall.AF_INET6},
		"igmp":     Protos{syscall.IPPROTO_IGMP, syscall.AF_INET},
		"igmp6":    Protos{syscall.IPPROTO_IGMP, syscall.AF_INET6},
		"raw":      Protos{syscall.IPPROTO_RAW, syscall.AF_INET},
		"raw6":     Protos{syscall.IPPROTO_RAW, syscall.AF_INET6},
		"packet":   Protos{syscall.IPPROTO_RAW, syscall.AF_PACKET},
	}

	options = []Protos{
		{syscall.IPPROTO_DCCP, syscall.AF_INET},
		{syscall.IPPROTO_DCCP, syscall.AF_INET6},
		{syscall.IPPROTO_ICMPV6, syscall.AF_INET6},
		{syscall.IPPROTO_ICMP, syscall.AF_INET},
		{syscall.IPPROTO_IGMP, syscall.AF_INET},
		{syscall.IPPROTO_IGMP, syscall.AF_INET6},
		{syscall.IPPROTO_RAW, syscall.AF_INET},
		{syscall.IPPROTO_RAW, syscall.AF_INET6},
		{syscall.IPPROTO_SCTP, syscall.AF_INET},
		{syscall.IPPROTO_SCTP, syscall.AF_INET6},
		{syscall.IPPROTO_TCP, syscall.AF_INET},
		{syscall.IPPROTO_TCP, syscall.AF_INET6},
		{syscall.IPPROTO_UDP, syscall.AF_INET},
		{syscall.IPPROTO_UDP, syscall.AF_INET6},
		{syscall.IPPROTO_UDPLITE, syscall.AF_INET},
		{syscall.IPPROTO_UDPLITE, syscall.AF_INET6},

		// for AF_PACKET, Type is the "Protocol" (SOCK_DGRAM, SOCK_RAW)
		{syscall.IPPROTO_RAW, unix.AF_PACKET},
		// here UDP is SOCK_DGRAM. Does not imply UDP protocol.
		{syscall.IPPROTO_UDP, unix.AF_PACKET},
		//{syscall.IPPROTO_IP, unix.AF_PACKET},
		//{unix.ETH_P_ALL, syscall.AF_PACKET},
	}
)

func Netstat(protos []string, states map[uint8]struct{}) []Socket {
	sckList := []Socket{}

	if len(protos) == 0 || protos[0] == "all" {
		for p := range knownProtos {
			protos = append(protos, p)
		}
	}

	files := ebpf.GetFileList("")
	inodes := make(map[uint32]ebpf.File)
	for _, f := range files {
		inode, err := strconv.Atoi(f.Inode)
		if err != nil {
			continue
		}
		inodes[uint32(inode)] = f
	}

	var ifname string
	filterStates := len(states) > 0
	for _, prot := range protos {
		if prot == "all" {
			continue
		}

		socketList, err := netlink.SocketsDump(knownProtos[prot].Fam, knownProtos[prot].Proto)
		if err != nil {
			log.Debug("%s netstat error: %s\n", prot, err)
			continue
		}

		for _, s := range socketList {
			if _, found := states[s.State]; filterStates && !found {
				continue
			}

			ifname = ""
			iface, _ := net.InterfaceByIndex(int(s.ID.Interface))
			if iface != nil {
				ifname = iface.Name
			}

			comm := ""
			exe := ""
			pid := ""
			ppid := ""
			host := ""
			if f, found := inodes[s.INode]; found {
				comm = f.Comm
				exe = f.Exe
				pid = f.Pid
				ppid = f.PPid
				host = f.Hostname
			}

			sckList = append(sckList, Socket{
				Conn:   s,
				Proto:  prot,
				Pid:    pid,
				Ppid:   ppid,
				Ifname: ifname,
				Host:   host,
				Exe:    exe,
				Comm:   comm,
			})
		}
	}

	return sckList
}

func Conntrack() {
	type famType struct {
		table uint8
		fam   ntl.InetFamily
	}
	families := []famType{
		{1, unix.AF_INET},
		{2, unix.AF_INET},
		{3, unix.AF_INET},
		{4, unix.AF_INET},
		{5, unix.AF_INET},
		{6, unix.AF_INET},
		{7, unix.AF_INET},
		{8, unix.AF_INET},
		{9, unix.AF_INET},
		{10, unix.AF_INET},
		{11, unix.AF_INET},
	}

	for tbl, family := range families {
		conns, err := ntl.ConntrackTableList(ntl.ConntrackTableType(family.table), family.fam)
		if err != nil {
			log.Error("table: %d, fam: %d, err: %v\n", tbl, family, err)
			continue
		}
		log.Log("---------------------------------- %d, %d -----------------------------------\n", tbl, family)
		for _, entry := range conns {
			log.Log("%s\n", entry)
		}
	}

}
