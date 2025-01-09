package subject

import (
	"client_siem/hash"
	"client_siem/hostinfo"
	"encoding/json"
	"time"
)

type Message struct {
	Message     string
	TypeMessage string
	HostName    string
	SystemOS    string
	HostIP      []string
	Time        time.Time
	TypeSubject SubjectType
	Json        string
	PID         string
	Username    string
}

func InitMessage(
	message string,
	typeMessage string,
	hostInfo hostinfo.HostInfo,
	subject Subject,
	PID string,
	Username string) Message {
	return Message{
		message,
		typeMessage,
		hostInfo.HostName,
		hostInfo.HostOS,
		hostInfo.IPs,
		time.Now(),
		subject.Type(),
		subject.JSON(),
		PID,
		Username}
}

func (m Message) JSON() string {
	bytes, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func (m Message) Type() SubjectType {
	return MessageT
}

func (m Message) Name() string {
	return m.JSON()
}

func (m Message) Hash(hash hash.Hash) string {
	return hash(m.JSON())
}
