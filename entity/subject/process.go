package subject

import (
	"client_siem/hash"
	"encoding/json"
	"time"
)

type Process struct {
	PID           string
	UID           string
	Nice          int32
	IsRunning     bool
	IsBackGround  bool
	CreateTime    time.Time
	Status        []string
	NameProcess   string
	CMDLine       string
	PercentCPU    float64
	PercentMemory float32
}

func (process Process) JSON() string {
	bytes, err := json.Marshal(process)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func (process Process) Type() SubjectType {
	return ProcessT
}

func (process Process) Name() string {
	return process.PID
}

func (process Process) Hash(hash hash.Hash) string {
	return hash(process.JSON())
}

func ProcessFromJSON(jsoned string) (Process, error) {
	var process Process
	err := json.Unmarshal([]byte(jsoned), &process)
	return process, err
}
