package subject

import (
	"client_siem/hash"
	"encoding/json"
	"time"
)

type File struct {
	FullName string
	Content  []byte
	Size     int64
	Mode     string
	Modified time.Time
}

func (file File) JSON() string {
	bytes, err := json.Marshal(file)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func (file File) Type() SubjectType {
	return FileT
}

func (file File) Name() string {
	return file.FullName
}

func (file File) Hash(hash hash.Hash) string {
	return hash(file.JSON())
}

func FileFromJSON(jsoned string) (File, error) {
	var file File
	err := json.Unmarshal([]byte(jsoned), &file)
	return file, err
}
