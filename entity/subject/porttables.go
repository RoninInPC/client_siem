package subject

import (
	"client_siem/hash"
	"encoding/json"
	"github.com/bastjan/netstat"
	"net"
	"strconv"
)

type SocketAddress struct {
	IP   net.IP
	Port uint16
}

type Protocol struct {
	Name string
	Path string
}

type LocalRemote struct {
	LocalAddress  string
	RemoteAddress *SocketAddress
	State         netstat.TCPState
	UserId        string
	PID           string
	Protocol      Protocol
	TransmitQueue uint64
	ReceiveQueue  uint64
}

type PortTables struct {
	Port         uint64
	LocalRemotes []LocalRemote
}

func (portTables PortTables) JSON() string {
	bytes, err := json.Marshal(portTables)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func (portTables PortTables) Type() SubjectType {
	return PortTablesT
}

func (portTables PortTables) Name() string {
	return strconv.Itoa(int(portTables.Port))
}

func (portTables PortTables) Hash(hash hash.Hash) string {
	return hash(portTables.JSON())
}

func PortTablesFromJSON(jsoned string) (PortTables, error) {
	var portTables PortTables
	err := json.Unmarshal([]byte(jsoned), &portTables)
	return portTables, err
}
