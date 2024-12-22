package entity

import (
	"client_siem/entity/subject"
	"client_siem/hostinfo"
	"time"
)

type Message struct {
	Message     string
	TypeMessage string
	HostName    string
	SystemOS    string
	HostIP      []string
	Time        time.Time
	TypeSubject subject.SubjectType
	JSON        string
}

func InitMessage(
	message string,
	typeMessage string,
	hostInfo hostinfo.HostInfo,
	subject subject.Subject) Message {
	return Message{
		message,
		typeMessage,
		hostInfo.HostName,
		hostInfo.HostOS,
		hostInfo.IPs,
		time.Now(),
		subject.Type(),
		subject.JSON()}
}
