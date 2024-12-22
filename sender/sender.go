package sender

import (
	"client_siem/entity/subject"
)

type Sender interface {
	Send(message subject.Message) bool
}
