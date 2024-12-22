package subject

import (
	"client_siem/hash"
	"encoding/json"
)

type User struct {
	Uid        string
	Gid        string
	Username   string
	SimpleName string
	HomeDir    string
}

func (user User) JSON() string {
	bytes, err := json.Marshal(user)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func (user User) Type() SubjectType {
	return UserT
}

func (user User) Name() string {
	return user.Username
}

func (user User) Hash(hash hash.Hash) string {
	return hash(user.JSON())
}

func UserFromJSON(jsoned string) (User, error) {
	var user User
	err := json.Unmarshal([]byte(jsoned), &user)
	return user, err
}
