package drivers

import "client_siem/entity/subject"

type Driver interface {
	GetSubjects() []subject.Subject
}
