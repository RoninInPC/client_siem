package scrapper

import (
	"client_siem/drivers"
	"client_siem/entity/subject"
	"time"
)

type FileScrapper struct {
	Driver     drivers.FileDriver
	stopScrape chan bool
}

func (s *FileScrapper) Scrape(channel chan subject.Subject, sleep time.Duration) {
	s.Driver.FileSystemCopy(channel)
}

func (s *FileScrapper) Stop() {

}
