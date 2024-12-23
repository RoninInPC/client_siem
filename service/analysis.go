package service

import (
	"client_siem/drivers"
	"client_siem/entity/subject"
	"client_siem/hostinfo"
	"client_siem/scrapper"
	"client_siem/sender"
	"client_siem/storage"
	"strconv"
	"strings"
	"time"
)

type Analysis struct {
	Scrappers     []scrapper.Scrapper
	Sender        sender.Sender
	Storage       storage.Storage
	FileDriver    drivers.FileDriver
	ProcessDriver drivers.ProcessDriver
	SleepDuration time.Duration
}

func (a Analysis) Work() {
	channel := make(chan subject.Subject)
	for _, s := range a.Scrappers {
		s.Scrape(channel, a.SleepDuration)
	}
	go func() {
		for sub := range channel {
			if sub.Type() == subject.SyscallT {
				a.Sender.Send(subject.InitMessage(
					"syscall",
					"syscall",
					hostinfo.GetHostInfo(),
					sub))
				syscall := sub.(subject.Syscall)
				syscallAnalyticsMap[sub.Name()](&a, syscall.Args, syscall.Ret)
			}
			if sub.Type() == subject.ProcessEnd {
				sub = subject.Process{PID: sub.Name()}
				a.Storage.Delete(sub)
				a.Sender.Send(subject.InitMessage(
					"delete",
					"delete",
					hostinfo.GetHostInfo(),
					sub))
				continue
			}
			if sub.Type() == subject.ProcessT {
				if !a.Storage.Exists(sub) {
					a.Storage.Update(sub)
					a.Sender.Send(subject.InitMessage(
						"update",
						"update",
						hostinfo.GetHostInfo(),
						sub))
				}
			}

		}
	}()
}

type SyscallAnalytics func(*Analysis, map[string]string, string)

func DeleteFile(a *Analysis, filename string) {
	sub := subject.File{FullName: filename}
	a.Storage.Delete(sub)
	a.Sender.Send(subject.InitMessage(
		"delete",
		"delete",
		hostinfo.GetHostInfo(),
		sub))
}

func DeleteProcess(a *Analysis, pid string) {
	sub := subject.Process{PID: pid}
	a.Storage.Delete(sub)
	a.Sender.Send(subject.InitMessage(
		"delete",
		"delete",
		hostinfo.GetHostInfo(),
		sub))
}

func DeleteDir(a *Analysis, filename string) {
	for name, _ := range a.Storage.GetType(subject.FileT) {
		if strings.Contains(name, filename) {
			DeleteFile(a, name)
		}
	}
}

func UpdateFile(a *Analysis, filename string) {
	sub := a.FileDriver.GetFile(filename)
	if !a.Storage.Exists(sub) {
		a.Storage.Update(sub)
		a.Sender.Send(subject.InitMessage(
			"update",
			"update",
			hostinfo.GetHostInfo(),
			sub))
	}
	if a.Storage.Get(sub) == "" {
		a.Storage.Add(sub)
		a.Sender.Send(subject.InitMessage(
			"new",
			"new",
			hostinfo.GetHostInfo(),
			sub))
	}
}

func RenameFile(a *Analysis, oldFilename, newFilename string) {
	DeleteProcess(a, oldFilename)
	UpdateFile(a, newFilename)
}

func NewProcess(a *Analysis, pid string) {
	sub := a.ProcessDriver.GetProcess(pid)
	if a.Storage.Get(sub) == "" {
		a.Storage.Add(sub)
		a.Sender.Send(subject.InitMessage(
			"new",
			"new",
			hostinfo.GetHostInfo(),
			sub))
	}
}

func Nope(a *Analysis, m map[string]string, ret string) {

}

var fds = map[string]string{}

func Open(a *Analysis, fd, name string) {
	fds[fd] = name
}

func Close(a *Analysis, fd string) {
	UpdateFile(a, fds[fd])
	delete(fds, fd)
}

var syscallAnalyticsMap = map[string]SyscallAnalytics{
	"copy_file_range": Nope,
	"open": func(analysis *Analysis, m map[string]string, ret string) {
		Open(analysis, m["filename"], ret)
	},
	"chmod": func(analysis *Analysis, m map[string]string, s string) {
		UpdateFile(analysis, m["filename"])
	},
	"chown": func(analysis *Analysis, m map[string]string, s string) {
		UpdateFile(analysis, m["filename"])
	},
	"renameat": func(analysis *Analysis, m map[string]string, s string) {
		oldname := m["oldname"]
		newname := m["newname"]
		if oldname == "" {
			oldname = fds[m["olddfd"]]
		}
		if newname == "" {
			newname = fds[m["newdfd"]]
		}
		RenameFile(analysis, oldname, newname)
	},
	"dup3": func(analysis *Analysis, m map[string]string, s string) {
		Open(analysis, m["newfd"], fds[m["newfd"]])
	},
	"dup": func(analysis *Analysis, m map[string]string, s string) {
		Open(analysis, s, fds[s])
	},
	"fchmodat": func(analysis *Analysis, m map[string]string, s string) {
		oldname := m["filename"]
		if oldname == "" {
			oldname = fds[m["dfd"]]
		}
		UpdateFile(analysis, oldname)
	},
	"rename": func(analysis *Analysis, m map[string]string, s string) {
		RenameFile(analysis, m["oldname"], m["newname"])
	},
	"fchmod": func(analysis *Analysis, m map[string]string, s string) {
		UpdateFile(analysis, m["filename"])
	},
	"openat2": func(analysis *Analysis, m map[string]string, s string) {
		oldname := m["filename"]
		if oldname == "" {
			oldname = fds[m["dfd"]]
		}
		Open(analysis, s, oldname)
	},
	"rmdir": func(analysis *Analysis, m map[string]string, s string) {
		DeleteDir(analysis, m["pathname"])
	},
	"close": func(analysis *Analysis, m map[string]string, s string) {
		Close(analysis, m["fd"])
	},
	"close_range": func(analysis *Analysis, m map[string]string, s string) {
		fd := m["fd"]
		max_fd := m["max_fd"]
		a, _ := strconv.Atoi(fd)
		b, _ := strconv.Atoi(max_fd)
		for a < b {
			Close(analysis, strconv.Itoa(a))
			a++
		}
	},
	"dup2": func(analysis *Analysis, m map[string]string, s string) {
		Open(analysis, m["newfd"], fds[m["oldfd"]])
	},
	"creat": func(analysis *Analysis, m map[string]string, s string) {
		Open(analysis, m["filename"], s)
	},
	"write": Nope,
	"openat": func(analysis *Analysis, m map[string]string, s string) {
		oldname := m["filename"]
		if oldname == "" {
			oldname = fds[m["dfd"]]
		}
		Open(analysis, s, oldname)
	},
	"truncate": func(analysis *Analysis, m map[string]string, s string) {
		UpdateFile(analysis, m["path"])
	},
	"chroot": Nope,
	"mknod": func(analysis *Analysis, m map[string]string, s string) {
		UpdateFile(analysis, m["filename"])
	},
	"mkdir":     Nope,
	"ftruncate": Nope,
	"renameat2": func(analysis *Analysis, m map[string]string, s string) {
		oldname := m["oldname"]
		newname := m["newname"]
		if oldname == "" {
			oldname = fds[m["olddfd"]]
		}
		if newname == "" {
			newname = fds[m["newdfd"]]
		}
		RenameFile(analysis, oldname, newname)
	},
	"fchownat": func(analysis *Analysis, m map[string]string, s string) {
		oldname := m["filename"]
		if oldname == "" {
			oldname = fds[m["dfd"]]
		}
		UpdateFile(analysis, oldname)
	},
	"mq_unlink": Nope,
	"pwritev":   Nope,
	"unlink": func(analysis *Analysis, m map[string]string, s string) {
		DeleteDir(analysis, m["pathname"])
	},
	"pwrite64": Nope,
	"pwrite2":  Nope,
	"symlink":  Nope,
	"unlinkat": func(analysis *Analysis, m map[string]string, s string) {
		oldname := m["pathname"]
		if oldname == "" {
			oldname = fds[m["dfd"]]
		}
		DeleteDir(analysis, oldname)
	},
	"fchown": Nope,
	"linkat": Nope,
	"tkill": func(analysis *Analysis, m map[string]string, s string) {
		DeleteProcess(analysis, m["pid"])
	},
	"kill": func(analysis *Analysis, m map[string]string, s string) {
		DeleteProcess(analysis, m["pid"])
	},
	"clone": func(analysis *Analysis, m map[string]string, s string) {
		NewProcess(analysis, s)
	},
	"execve":   Nope,
	"execveat": Nope,
	"fork": func(analysis *Analysis, m map[string]string, s string) {
		NewProcess(analysis, s)
	},
	"vfork": func(analysis *Analysis, m map[string]string, s string) {
		NewProcess(analysis, s)
	},
	"tgkill": func(analysis *Analysis, m map[string]string, s string) {
		DeleteProcess(analysis, m["pid"])
	},
	"clone3": func(analysis *Analysis, m map[string]string, s string) {
		NewProcess(analysis, s)
	},
	"sethostname":   Nope,
	"setdomainname": Nope,
	"sysinfo":       Nope,
}
