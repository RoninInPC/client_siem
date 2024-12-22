package drivers

import (
	"client_siem/entity/subject"
	"github.com/bastjan/netstat"
	"strconv"
)

type PortTablesDriver struct {
}

func (portTablesDriver PortTablesDriver) GetSubjects() []subject.PortTables {
	return GetTable()
}

func GetTable() []subject.PortTables {
	portTables := make([]subject.PortTables, 0)

	table, _ := netstat.TCP.Connections()
	connections, _ := netstat.TCP6.Connections()
	table = append(table, connections...)
	connections, _ = netstat.UDP.Connections()
	table = append(table, connections...)
	connections, _ = netstat.UDP6.Connections()
	table = append(table, connections...)
	m := make(map[int][]subject.LocalRemote)
	for _, connection := range connections {
		_, ok := m[connection.Port]
		if !ok {
			m[connection.Port] = make([]subject.LocalRemote, 0)
		} else {
			m[connection.Port] = append(m[connection.Port], ConnectionToEntity(connection))
		}
	}
	for port, remotes := range m {
		portTables = append(portTables, subject.PortTables{
			Port:         uint64(port),
			LocalRemotes: remotes})
	}
	return portTables
}

func ConnectionToEntity(con *netstat.Connection) subject.LocalRemote {
	return subject.LocalRemote{
		LocalAddress:  con.IP.String(),
		RemoteAddress: &subject.SocketAddress{IP: con.RemoteIP, Port: uint16(con.RemotePort)},
		State:         con.State,
		UserId:        con.UserID,
		PID:           strconv.Itoa(con.Pid),
		Protocol:      subject.Protocol{Name: con.Protocol.Name, Path: con.Protocol.RelPath},
		TransmitQueue: con.TransmitQueue,
		ReceiveQueue:  con.ReceiveQueue,
	}
}
