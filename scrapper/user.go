package scrapper

import (
	"client_siem/drivers"
	"client_siem/entity/subject"
	"time"
)

type UserScrapper struct {
	Driver     drivers.UserDriver
	stopScrape chan bool
}

func (s *UserScrapper) Scrape(channel chan subject.Subject, sleep time.Duration) {
	s.stopScrape = make(chan bool)
	go func() {
		for {
			select {
			case <-s.stopScrape:
				close(s.stopScrape)
				return
			default:
				for _, f := range s.Driver.GetSubjects() {
					channel <- f
				}
				time.Sleep(sleep)
			}
		}
	}()
}

func (s *UserScrapper) Stop() {
	s.stopScrape <- true
}
