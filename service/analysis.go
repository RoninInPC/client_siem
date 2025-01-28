package service

import (
	"client_siem/drivers"
	"client_siem/entity/subject"
	"client_siem/hostinfo"
	"client_siem/scrapper"
	"client_siem/sender"
	"client_siem/storagesubjects"
	"fmt"
	"github.com/RoninInPC/pwdx"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type Analysis struct {
	Scrappers []scrapper.Scrapper
	Sender    sender.Sender
	Storage   storagesubjects.Storage
	//StorageFD     storagefd.StorageFD
	FileDriver    drivers.FileDriver
	ProcessDriver drivers.ProcessDriver
	UserDriver    drivers.UserDriver
	PortDriver    drivers.PortTablesDriver
	SleepDuration time.Duration
}

func (a Analysis) Work() {
	pid := strconv.Itoa(os.Getpid())
	channel := make(chan subject.Subject)
	for _, s := range a.Scrappers {
		s.Scrape(channel, a.SleepDuration)
	}

	func() {
		for sub := range channel {
			if sub.Type() == subject.SyscallT {
				syscall := sub.(subject.Syscall)
				if a.ProcessDriver.IsChild(syscall.PID, pid) {
					continue
				}
				a.Sender.Send(subject.InitMessage(
					"syscall",
					"syscall",
					hostinfo.GetHostInfo(),
					sub,
					syscall.PID,
					syscall.Username))
				function, exists := syscallAnalyticsMap[sub.Name()]
				if exists {
					function(&a, syscall)
				} else {
					println(sub.Name())
				}

			}
			if sub.Type() == subject.ProcessEnd {
				sub = subject.Process{PID: sub.Name()}
				a.Storage.Delete(sub)
				a.Sender.Send(subject.InitMessage(
					"delete",
					"delete",
					hostinfo.GetHostInfo(),
					sub,
					sub.Name(),
					"",
				))
				continue
			}
			if sub.Type() == subject.ProcessT {
				if !a.Storage.Exists(sub) {
					a.Storage.Update(sub)
					a.Sender.Send(subject.InitMessage(
						"update",
						"update",
						hostinfo.GetHostInfo(),
						sub,
						sub.Name(),
						""))
				}
			}

		}
	}()
}

func GetFullFileNameByProcess(pid string, filename string) string {
	pidInt, _ := strconv.Atoi(pid)
	f := filename
	if path.Base(filename) == filename {
		return pwdx.Pwdx(pidInt).Dir() + "/" + filename
	}
	println(pid, f, filename)
	return filename
}

type SyscallAnalytics func(*Analysis, subject.Syscall)

func DeleteFile(a *Analysis, pid, username, filename string) {
	filename = GetFullFileNameByProcess(pid, filename)
	sub := subject.File{FullName: filename}
	a.Storage.Delete(sub)
	a.Sender.Send(subject.InitMessage(
		"delete",
		"delete",
		hostinfo.GetHostInfo(),
		sub,
		pid,
		username))
}

func DeleteProcess(a *Analysis, pid, username string) {
	sub := subject.Process{PID: pid}
	a.Storage.Delete(sub)
	a.Sender.Send(subject.InitMessage(
		"delete",
		"delete",
		hostinfo.GetHostInfo(),
		sub,
		pid,
		username))
}

func DeleteDir(a *Analysis, pid, username, filename string) {
	filename = GetFullFileNameByProcess(pid, filename)
	for name, _ := range a.Storage.GetType(subject.FileT) {
		if strings.Contains(name, filename) {
			DeleteFile(a, pid, username, name)
		}
	}
}

func UpdateFile(a *Analysis, pid, username, filename string) {
	filename = GetFullFileNameByProcess(pid, filename)
	println(pid, filename)
	if a.AnalysisUserPort(pid, username, filename) {
		return
	}
	sub, err := a.FileDriver.GetFile(filename)
	if err != nil {
		return
	}
	if !a.Storage.Exists(sub) {
		a.Storage.Update(sub)
		a.Sender.Send(subject.InitMessage(
			"update",
			"update",
			hostinfo.GetHostInfo(),
			sub,
			pid,
			username))
	}
	if a.Storage.Get(sub) == "" {
		a.Storage.Add(sub)
		a.Sender.Send(subject.InitMessage(
			"new",
			"new",
			hostinfo.GetHostInfo(),
			sub,
			pid,
			username))
	}
}

func RenameFile(a *Analysis, pid, username, oldFilename, newFilename string) {
	oldFilename = GetFullFileNameByProcess(pid, oldFilename)
	newFilename = GetFullFileNameByProcess(pid, newFilename)
	DeleteFile(a, pid, username, oldFilename)
	UpdateFile(a, pid, username, newFilename)
}

func NewProcess(a *Analysis, pid, username string) {
	sub := a.ProcessDriver.GetProcess(pid)
	if a.Storage.Get(sub) == "" {
		a.Storage.Add(sub)
		a.Sender.Send(subject.InitMessage(
			"new",
			"new",
			hostinfo.GetHostInfo(),
			sub,
			pid,
			username))
	}
}

func Nope(a *Analysis, s subject.Syscall) {

}

func Open(a *Analysis, pid, fd, name string) {
	//a.StorageFD.Add(pid, fd, name)
}

func Close(a *Analysis, pid, username, fd string) {
	UpdateFile(a, pid, username, getFileNameByDescriptor(pid, fd))
	//a.StorageFD.Delete(pid, fd)
}

var syscallAnalyticsMap = map[string]SyscallAnalytics{
	"copy_file_range": Nope,
	"open": func(analysis *Analysis, s subject.Syscall) {
		Open(analysis, s.PID, s.Ret, s.Args["filename"])
	},
	"chmod": func(analysis *Analysis, s subject.Syscall) {
		UpdateFile(analysis, s.PID, s.Username, s.Args["filename"])
	},
	"chown": func(analysis *Analysis, s subject.Syscall) {
		UpdateFile(analysis, s.PID, s.Username, s.Args["filename"])
	},
	"renameat": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["oldname"]
		newname := s.Args["newname"]
		if oldname == "" {
			oldname = getFileNameByDescriptor(s.PID, s.Args["olddfd"])
		}
		if newname == "" {
			newname = getFileNameByDescriptor(s.PID, s.Args["newdfd"])
		}
		RenameFile(analysis, s.PID, s.Username, oldname, newname)
	},
	"dup3": func(analysis *Analysis, s subject.Syscall) {
		Open(analysis, s.PID, s.Ret, getFileNameByDescriptor(s.PID, s.Args["oldfd"]))
	},
	"dup": func(analysis *Analysis, s subject.Syscall) {
		Open(analysis, s.PID, s.Ret, getFileNameByDescriptor(s.PID, s.Args["oldfd"]))
	},
	"fchmodat": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["filename"]
		if oldname == "" {
			oldname = getFileNameByDescriptor(s.PID, s.Args["dfd"])
		}
		UpdateFile(analysis, s.PID, s.Username, oldname)
	},
	"rename": func(analysis *Analysis, s subject.Syscall) {
		RenameFile(analysis, s.PID, s.Username, s.Args["oldname"], s.Args["newname"])
	},
	"fchmod": func(analysis *Analysis, s subject.Syscall) {
		UpdateFile(analysis, s.PID, s.Username, s.Args["filename"])
	},
	"openat2": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["filename"]
		if oldname == "" {
			oldname = getFileNameByDescriptor(s.PID, s.Args["dfd"])
		}
		Open(analysis, s.PID, s.Ret, oldname)
	},
	"rmdir": func(analysis *Analysis, s subject.Syscall) {
		DeleteDir(analysis, s.PID, s.Username, s.Args["pathname"])
	},
	"close": func(analysis *Analysis, s subject.Syscall) {
		Close(analysis, s.PID, s.Username, s.Args["fd"])
	},
	"close_range": func(analysis *Analysis, s subject.Syscall) {
		fd := s.Args["fd"]
		max_fd := s.Args["max_fd"]
		a, _ := strconv.Atoi(fd)
		b, _ := strconv.Atoi(max_fd)
		for a < b {
			Close(analysis, s.PID, s.Username, strconv.Itoa(a))
			a++
		}
	},
	"dup2": func(analysis *Analysis, s subject.Syscall) {
		Open(analysis, s.PID, s.Ret, getFileNameByDescriptor(s.PID, s.Args["oldfd"]))
	},
	"creat": func(analysis *Analysis, s subject.Syscall) {
		Open(analysis, s.PID, s.Ret, s.Args["filename"])
	},
	"write": Nope,
	"openat": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["filename"]
		if oldname == "" {
			oldname = getFileNameByDescriptor(s.PID, s.Args["dfd"])
		}
		Open(analysis, s.PID, s.Ret, oldname)
	},
	"truncate": func(analysis *Analysis, s subject.Syscall) {
		UpdateFile(analysis, s.PID, s.Username, s.Args["path"])
	},
	"chroot": Nope,
	"mknod": func(analysis *Analysis, s subject.Syscall) {
		UpdateFile(analysis, s.PID, s.Username, s.Args["filename"])
	},
	"mkdir":     Nope,
	"ftruncate": Nope,
	"renameat2": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["oldname"]
		newname := s.Args["newname"]
		if oldname == "" {
			oldname = getFileNameByDescriptor(s.PID, s.Args["olddfd"])
		}
		if newname == "" {
			newname = getFileNameByDescriptor(s.PID, s.Args["newdfd"])
		}
		RenameFile(analysis, s.PID, s.Username, oldname, newname)
	},
	"fchownat": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["filename"]
		if oldname == "" {
			oldname = getFileNameByDescriptor(s.PID, s.Args["dfd"])
		}
		UpdateFile(analysis, s.PID, s.Username, oldname)
	},
	"mq_unlink": Nope,
	"pwritev":   Nope,
	"unlink": func(analysis *Analysis, s subject.Syscall) {
		DeleteDir(analysis, s.PID, s.Username, s.Args["pathname"])
	},
	"pwrite64": Nope,
	"pwrite2":  Nope,
	"symlink":  Nope,
	"unlinkat": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["pathname"]
		if oldname == "" {
			oldname = getFileNameByDescriptor(s.PID, s.Args["dfd"])
		}
		DeleteDir(analysis, s.PID, s.Username, oldname)
	},
	"fchown": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["filename"]
		if oldname == "" {
			oldname = getFileNameByDescriptor(s.PID, s.Args["dfd"])
		}
		UpdateFile(analysis, s.PID, s.Username, oldname)
	},
	"linkat": Nope,
	"tkill": func(analysis *Analysis, s subject.Syscall) {
		DeleteProcess(analysis, s.Args["pid"], s.Username)
	},
	"kill": func(analysis *Analysis, s subject.Syscall) {
		DeleteProcess(analysis, s.Args["pid"], s.Username)
	},
	"clone": func(analysis *Analysis, s subject.Syscall) {
		NewProcess(analysis, s.Ret, s.Username)
	},
	"execve":   Nope,
	"execveat": Nope,
	"fork": func(analysis *Analysis, s subject.Syscall) {
		NewProcess(analysis, s.Ret, s.Username)
	},
	"vfork": func(analysis *Analysis, s subject.Syscall) {
		NewProcess(analysis, s.Ret, s.Username)
	},
	"tgkill": func(analysis *Analysis, s subject.Syscall) {
		DeleteProcess(analysis, s.Args["pid"], s.Username)
	},
	"clone3": func(analysis *Analysis, s subject.Syscall) {
		NewProcess(analysis, s.Ret, s.Username)
	},
	"sethostname":   Nope,
	"setdomainname": Nope,
	"sysinfo":       Nope,
}

func IsPasswd(pathname string) bool {
	return pathname == "/etc/passwd"
}

func IsNet(pathname string) bool {
	return strings.HasPrefix(pathname, "/proc/net")
}

func (analysis *Analysis) AnalysisUserPort(pid, username, pathname string) bool {
	if IsPasswd(pathname) {
		analysis.AnalysisUser(pid, username)
		return true
	}
	if IsNet(pathname) {
		analysis.AnalysisPort(pid, username)
		return true
	}
	return false
}

func (analysis *Analysis) AnalysisUser(pid, username string) {
	users := analysis.UserDriver.GetSubjects()
	for _, user := range users {
		if analysis.Storage.Get(user) == "" {
			analysis.Storage.Add(user)
			analysis.Sender.Send(subject.InitMessage(
				"new",
				"new",
				hostinfo.GetHostInfo(),
				user,
				pid,
				username))
		}
		if analysis.Storage.Exists(user) {
			analysis.Storage.Update(user)
			analysis.Sender.Send(subject.InitMessage(
				"update",
				"update",
				hostinfo.GetHostInfo(),
				user,
				pid,
				username))
		}
	}
	for name, _ := range analysis.Storage.GetType(subject.UserT) {
		_, err := analysis.UserDriver.GetUser(name)
		if err != nil {
			sub := subject.File{FullName: name}
			analysis.Storage.Delete(sub)
			analysis.Sender.Send(subject.InitMessage(
				"delete",
				"delete",
				hostinfo.GetHostInfo(),
				sub,
				pid,
				username))
		}
	}
}

func (analysis *Analysis) AnalysisPort(pid, username string) {
	ports := analysis.PortDriver.GetSubjects()
	for _, port := range ports {
		if analysis.Storage.Get(port) == "" {
			analysis.Storage.Add(port)
			analysis.Sender.Send(subject.InitMessage(
				"new",
				"new",
				hostinfo.GetHostInfo(),
				port,
				pid,
				username))
		}
		if analysis.Storage.Exists(port) {
			analysis.Storage.Update(port)
			analysis.Sender.Send(subject.InitMessage(
				"update",
				"update",
				hostinfo.GetHostInfo(),
				port,
				pid,
				username))
		}
	}
	for name, _ := range analysis.Storage.GetType(subject.PortTablesT) {
		_, err := analysis.PortDriver.GetPort(name)
		if err != nil {
			port, _ := strconv.Atoi(name)
			sub := subject.PortTables{Port: uint64(port)}
			analysis.Storage.Delete(sub)
			analysis.Sender.Send(subject.InitMessage(
				"delete",
				"delete",
				hostinfo.GetHostInfo(),
				sub,
				pid,
				username))
		}
	}
}

func getFileNameByDescriptor(pid string, fd string) string {
	filename, err := os.Readlink(fmt.Sprintf("/proc/%s/fd/%s", pid, fd))
	if err != nil {
		return ""
	}
	return filename
}
