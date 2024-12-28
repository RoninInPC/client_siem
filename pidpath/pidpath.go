package pidpath

import (
	"path"
)

type PIDPath map[string]string

var pidPath = PIDPath{}

func SetPidPath(pid, path string) {
	pidPath[pid] = path
}

func GetPath(pid string) string {
	ans, ok := pidPath[pid]
	if !ok {
		return ""
	}
	return ans
}

func DeletePID(pid string) {
	delete(pidPath, pid)
}

func CheckFilename(pid, filename string) string {
	p := GetPath(pid)
	if p != "" {
		return ""
	}
	if path.Base(filename) == filename {
		return p + filename
	}
	return filename
}
