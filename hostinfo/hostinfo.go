package hostinfo

import (
	"github.com/shirou/gopsutil/host"
	"net"
)

type HostInfo struct {
	HostName string
	HostOS   string
	IPs      []string
}

var (
	hostName string
	hostOS   string
	ips      []string
)

func HostInfoInit() {
	info, _ := host.Info()
	hostName = info.Hostname
	hostOS = info.OS
	ips, _ = getLocalIPs()
}

func getLocalIPs() ([]string, error) {
	var ips []string
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addresses {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	return ips, nil
}

func GetHostInfo() HostInfo {
	return HostInfo{hostName, hostOS, ips}
}
