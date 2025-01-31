package scrapper

import (
	"client_siem/drivers"
	"client_siem/entity/subject"
	"slices"
	"time"
)

type ProcessScrapper struct {
	Driver     drivers.ProcessDriver
	stopScrape chan bool
}

func (s ProcessScrapper) Scrape(channel chan subject.Subject, sleep time.Duration) {
	s.stopScrape = make(chan bool)
	pids := make([]string, 0)
	go func() {
		for {
			select {
			case <-s.stopScrape:
				close(s.stopScrape)
				return
			default:
				for _, f := range s.Driver.GetSubjects() {
					p := f.(subject.Process)
					channel <- f
					if !slices.Contains(pids, p.PID) {
						pids = append(pids, p.PID)
					}
				}
				time.Sleep(sleep)
			}
		}
	}()
}

func (s ProcessScrapper) Stop() {
	s.stopScrape <- true
}
