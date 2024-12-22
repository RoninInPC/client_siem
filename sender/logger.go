package sender

import (
	"client_siem/entity/subject"
	"log"
)

type Logger struct {
}

func (logger *Logger) Send(subject subject.Message) bool {
	log.Println(subject)
	return true
}
