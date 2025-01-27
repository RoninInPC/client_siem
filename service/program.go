package service

import (
	"client_siem/config"
	"client_siem/drivers"
	"client_siem/hash"
	"client_siem/hostinfo"
	"client_siem/scrapper"
	"client_siem/sender"
	redis2 "client_siem/storagefd/redis"
	"client_siem/storagesubjects/redis"
	"time"
)

type Program struct {
	InitService     Initialization
	AnalysisService Analysis
}

func InitProgram(fileName string) *Program {
	hostinfo.HostInfoInit()
	conf, err := config.ReadFromFile(fileName)
	if err != nil {
		panic(err)
	}
	s := sender.InitJWTSender(conf.Host.HostAddress)
	redisStorage := redis.Init(
		conf.RedisSubjectBase.Address,
		conf.RedisSubjectBase.Password,
		conf.RedisSubjectBase.DB, hash.ToMD5)
	redisFDStorage := redis2.InitFD(
		conf.RedisFDStorage.Address,
		conf.RedisFDStorage.Password,
		conf.RedisFDStorage.DB)
	i := Initialization{
		Key:          conf.Key.PrivateKey,
		FileScrapper: scrapper.FileScrapper{Driver: drivers.FileDriver{Path: "/"}},
		Drivers: []drivers.Driver{
			drivers.UserDriver{},
			drivers.ProcessDriver{},
			drivers.PortTablesDriver{}},
		Storage: redisStorage,
		Sender:  s,
	}
	c := make(chan bool)
	a := Analysis{
		Sender: s,
		Scrappers: []scrapper.Scrapper{
			scrapper.InitSyscallScrapper(c),
			scrapper.InitPIDChecker(redisStorage, drivers.ProcessDriver{}, c),
		},
		Storage:       redisStorage,
		StorageFD:     redisFDStorage,
		FileDriver:    drivers.FileDriver{Path: "/"},
		ProcessDriver: drivers.ProcessDriver{},
		UserDriver:    drivers.UserDriver{},
		PortDriver:    drivers.PortTablesDriver{},
		SleepDuration: time.Minute * 10,
	}
	return &Program{i, a}

}

func (program *Program) Work() {
	program.InitService.Work()
	time.Sleep(time.Second * 10)
	program.AnalysisService.Work()
}
