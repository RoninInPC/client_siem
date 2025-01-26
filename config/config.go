package config

import (
	"gopkg.in/ini.v1"
)

type Config struct {
	Host struct {
		HostAddress string `ini:"host_address"`
	} `ini:"host"`
	Key struct {
		PrivateKey string `ini:"private_key"`
	} `ini:"key"`
	RedisSubjectBase struct {
		Address  string `ini:"address"`
		Password string `ini:"password"`
		DB       int    `ini:"db"`
	} `ini:"redis_subject_base"`
	RedisFDStorage struct {
		Address  string `ini:"address"`
		Password string `ini:"password"`
		DB       int    `ini:"db"`
	} `ini:"redis_fd_base"`
}

func ReadFromFile(fileName string) (Config, error) {
	cfg, err := ini.Load(fileName)
	config := Config{}
	if err != nil {
		return Config{}, err
	}
	err = cfg.MapTo(&config)
	if err != nil {
		return Config{}, err
	}
	return config, nil
}
