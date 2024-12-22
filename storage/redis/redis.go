package redis

import (
	"client_siem/entity/subject"
	"client_siem/hash"
	red "github.com/go-redis/redis"
)

type RedisStorage struct {
	client *red.Client
	hash   hash.Hash
}

func Init(address string, passwd string, db int, hash hash.Hash) *RedisStorage {
	client := red.NewClient(
		&red.Options{
			Addr:     address,
			Password: passwd,
			DB:       db})
	return &RedisStorage{client: client, hash: hash}
}

func (storage *RedisStorage) Add(s subject.Subject) bool {
	return storage.client.HSet(choose(s.Type()), s.Name(), s.Hash(storage.hash)).Err() == nil
}

func (storage *RedisStorage) Update(s subject.Subject) bool {
	return storage.client.HSet(choose(s.Type()), s.Name(), s.Hash(storage.hash)).Err() == nil
}

func (storage *RedisStorage) Get(s subject.Subject) string {
	return storage.client.HGet(choose(s.Type()), s.Name()).String()
}

func (storage *RedisStorage) Exists(s subject.Subject) bool {
	return storage.Get(s) == s.Hash(storage.hash)
}

func (storage *RedisStorage) GetType(s subject.SubjectType) map[string]string {
	return storage.client.HGetAll(choose(s)).Val()
}

func (storage *RedisStorage) Delete(s subject.Subject) bool {
	return storage.client.HDel(choose(s.Type()), s.Name()).Err() == nil
}

func choose(subjectType subject.SubjectType) string {
	switch subjectType {
	case subject.FileT:
		return "file"
	case subject.ProcessT:
		return "process"
	case subject.UserT:
		return "user"
	case subject.PortTablesT:
		return "port_tables"
	default:
		return "unknown"
	}
}
