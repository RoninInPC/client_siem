package scrapper

import (
	"client_siem/drivers"
	"client_siem/entity/subject"
	"client_siem/entity/subject/notification"
	"client_siem/storagesubjects"
	"time"
)

type PIDChecker struct {
	Storage    storagesubjects.Storage
	Driver     drivers.ProcessDriver
	stopScrape chan bool
}

func (s *PIDChecker) Scrape(channel chan subject.Subject, sleep time.Duration) {
	s.stopScrape = make(chan bool)
	go func() {
		for {
			select {
			case <-s.stopScrape:
				close(s.stopScrape)
				return
			default:
				for pid, _ := range s.Storage.GetType(subject.ProcessT) {
					if !s.Driver.Exists(pid) {
						channel <- notification.NotificationProcessEnd{PID: pid}
					}
				}
				for _, process := range s.Driver.GetSubjects() {
					channel <- process
				}
				time.Sleep(sleep)
			}
		}
	}()
}

func (s *PIDChecker) Stop() {
	s.stopScrape <- true
}
