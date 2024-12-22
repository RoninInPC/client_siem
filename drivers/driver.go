package drivers

import "client_siem/entity/subject"

type Driver[s subject.Subject] interface {
	GetSubjects() []s
}
