package service

import (
	"client_siem/drivers"
	"client_siem/entity/subject"
	"client_siem/hash"
	"client_siem/hostinfo"
	"client_siem/sender"
	"client_siem/storage"
	"time"
)

type Initialization struct {
	Drivers []drivers.Driver[subject.Subject]
	Sender  sender.Sender
	Storage storage.Storage
	Key     string
}

func (init Initialization) Work() {
	init.Sender.Send(sender.InitInitializationMessage(init.Key, hash.ToMD5))
	time.Sleep(time.Second)
	for _, driver := range init.Drivers {
		for _, s := range driver.GetSubjects() {
			init.Storage.Add(s)
			init.Sender.Send(subject.InitMessage("", "init", hostinfo.GetHostInfo(), s))
		}
	}
}
