package hash

import (
	"crypto/md5"
	"fmt"
	"github.com/deatil/go-md6"
	"strings"
)

type Hash func(string) string

func ToMD6(str string) string {
	h := md6.New256()
	h.Write([]byte(str))
	sum := h.Sum(nil)
	return string(sum)
}

func ToMD5(str string) string {
	data := []byte(str)
	hash := fmt.Sprintf("%x", md5.Sum(data))
	return hash
}

func (h Hash) ToHash(args ...string) string {
	return h(strings.Join(args, ""))
}
