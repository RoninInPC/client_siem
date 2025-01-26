package redis

import red "github.com/go-redis/redis"

type RedisStorageFD struct {
	client *red.Client
}

func (storage *RedisStorageFD) Add(pid, fd, name string) bool {
	return storage.client.HSet(pid, fd, name).Err() == nil
}

func (storage *RedisStorageFD) Get(pid, fd string) string {
	return storage.client.HGet(pid, fd).Val()
}

func (storage *RedisStorageFD) Delete(pid, fd string) bool {
	return storage.client.HDel(pid, fd).Err() == nil
}

func InitFD(address string, passwd string, db int) *RedisStorageFD {
	client := red.NewClient(
		&red.Options{
			Addr:     address,
			Password: passwd,
			DB:       db})
	return &RedisStorageFD{client: client}
}
