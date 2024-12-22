package notification

import "client_siem/entity/subject"

type Notification interface {
	subject.Subject
}
