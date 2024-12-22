package notification

import (
	"client_siem/entity/subject"
	"client_siem/hash"
	"encoding/json"
)

type NotificationProcessEnd struct {
	PID string
}

func (n NotificationProcessEnd) JSON() string {
	bytes, err := json.Marshal(n)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func (n NotificationProcessEnd) Name() string {
	return n.PID
}

func (n NotificationProcessEnd) Type() subject.SubjectType {
	return subject.ProcessEnd
}

func (n NotificationProcessEnd) Hash(hash hash.Hash) string {
	return hash(n.JSON())
}
