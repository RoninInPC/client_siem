package storage

import "client_siem/entity/subject"

type Storage interface {
	Add(subject.Subject) bool
	Update(subject.Subject) bool
	Get(subject.Subject) string
	Exists(subject.Subject) bool
	GetType(subject.SubjectType) map[string]string
	Delete(subject.Subject) bool
}
