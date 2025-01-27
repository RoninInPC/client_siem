package hash

import (
	"crypto/md5"
	"fmt"
	"strings"
)

type Hash func(string) string

func ToMD5(str string) string {
	data := []byte(str)
	hash := fmt.Sprintf("%x", md5.Sum(data))
	return hash
}

func (h Hash) ToHash(args ...string) string {
	return h(strings.Join(args, ""))
}
