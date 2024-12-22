package scrapper

import (
	"client_siem/entity/subject"
	"time"
)

type Scrapper interface {
	Scrape(chan subject.Subject, time.Duration)
	Stop()
}
