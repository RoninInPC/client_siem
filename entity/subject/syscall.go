package subject

import (
	"client_siem/hash"
	"encoding/json"
	"github.com/RoninInPC/gosyscalltrace"
)

type Syscall struct {
	gosyscalltrace.TraceInfo
	Username string
}

func (m Syscall) JSON() string {
	bytes, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func (m Syscall) Type() SubjectType {
	return SyscallT
}

func (m Syscall) Name() string {
	return m.SyscallName
}

func (m Syscall) Hash(hash hash.Hash) string {
	return hash(m.JSON())
}
