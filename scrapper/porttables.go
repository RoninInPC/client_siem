package scrapper

import (
	"client_siem/drivers"
	"client_siem/entity/subject"
	"time"
)

type PortTablesScrapper struct {
	Driver     drivers.PortTablesDriver
	stopScrape chan bool
}

func (s *PortTablesScrapper) Scrape(channel chan subject.Subject, sleep time.Duration) {
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

func (s *PortTablesScrapper) Stop() {
	s.stopScrape <- true
}
