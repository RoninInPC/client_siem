package service

import (
	"client_siem/drivers"
	"client_siem/entity/subject"
	"client_siem/hostinfo"
	"client_siem/pidpath"
	"client_siem/scrapper"
	"client_siem/sender"
	"client_siem/storage"
	"os"
	"strconv"
	"strings"
	"time"
)

type Analysis struct {
	Scrappers           []scrapper.Scrapper
	ScrappersUsersPorts []scrapper.Scrapper
	Sender              sender.Sender
	Storage             storage.Storage
	FileDriver          drivers.FileDriver
	ProcessDriver       drivers.ProcessDriver
	SleepDuration       time.Duration
}

func (a Analysis) Work() {
	pid := strconv.Itoa(os.Getpid())
	channel := make(chan subject.Subject)
	channelUsersPorts := make(chan subject.Subject)
	for _, s := range a.Scrappers {
		s.Scrape(channel, a.SleepDuration)
	}

	for _, s := range a.Scrappers {
		s.Scrape(channelUsersPorts, a.SleepDuration*10)
	}

	go func() {
		for sub := range channelUsersPorts {
			if sub.Type() == subject.UserT || sub.Type() == subject.PortTablesT {
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
		}
	}()

	go func() {
		for sub := range channel {
			if sub.Type() == subject.SyscallT {
				syscall := sub.(subject.Syscall)

				if syscall.PID == pid {
					continue
				}

				a.Sender.Send(subject.InitMessage(
					"syscall",
					"syscall",
					hostinfo.GetHostInfo(),
					sub))
				syscallAnalyticsMap[sub.Name()](&a, syscall)
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

type SyscallAnalytics func(*Analysis, subject.Syscall)

func DeleteFile(a *Analysis, pid, filename string) {
	filename = pidpath.CheckFilename(pid, filename)
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
	pidpath.DeletePID(pid)
	a.Storage.Delete(sub)
	a.Sender.Send(subject.InitMessage(
		"delete",
		"delete",
		hostinfo.GetHostInfo(),
		sub))
}

func DeleteDir(a *Analysis, pid, filename string) {
	filename = pidpath.CheckFilename(pid, filename)
	for name, _ := range a.Storage.GetType(subject.FileT) {
		if strings.Contains(name, filename) {
			DeleteFile(a, pid, name)
		}
	}
}

func UpdateFile(a *Analysis, pid, filename string) {
	filename = pidpath.CheckFilename(pid, filename)
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

func RenameFile(a *Analysis, pid, oldFilename, newFilename string) {
	oldFilename = pidpath.CheckFilename(pid, oldFilename)
	newFilename = pidpath.CheckFilename(pid, newFilename)
	DeleteFile(a, pid, oldFilename)
	UpdateFile(a, pid, newFilename)
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

func Nope(a *Analysis, s subject.Syscall) {

}

var fds = map[string]string{}

func Open(a *Analysis, fd, name string) {
	fds[fd] = name
}

func Close(a *Analysis, pid, fd string) {
	UpdateFile(a, pid, fds[fd])
	delete(fds, fd)
}

var syscallAnalyticsMap = map[string]SyscallAnalytics{
	"copy_file_range": Nope,
	"open": func(analysis *Analysis, s subject.Syscall) {
		Open(analysis, s.Args["filename"], s.Ret)
	},
	"chmod": func(analysis *Analysis, s subject.Syscall) {
		UpdateFile(analysis, s.PID, s.Args["filename"])
	},
	"chown": func(analysis *Analysis, s subject.Syscall) {
		UpdateFile(analysis, s.PID, s.Args["filename"])
	},
	"renameat": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["oldname"]
		newname := s.Args["newname"]
		if oldname == "" {
			oldname = fds[s.Args["olddfd"]]
		}
		if newname == "" {
			newname = fds[s.Args["newdfd"]]
		}
		RenameFile(analysis, s.PID, oldname, newname)
	},
	"dup3": func(analysis *Analysis, s subject.Syscall) {
		Open(analysis, s.Args["newfd"], fds[s.Args["newfd"]])
	},
	"dup": func(analysis *Analysis, s subject.Syscall) {
		Open(analysis, s.Ret, fds[s.Ret])
	},
	"fchmodat": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["filename"]
		if oldname == "" {
			oldname = fds[s.Args["dfd"]]
		}
		UpdateFile(analysis, s.PID, oldname)
	},
	"rename": func(analysis *Analysis, s subject.Syscall) {
		RenameFile(analysis, s.PID, s.Args["oldname"], s.Args["newname"])
	},
	"fchmod": func(analysis *Analysis, s subject.Syscall) {
		UpdateFile(analysis, s.PID, s.Args["filename"])
	},
	"openat2": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["filename"]
		if oldname == "" {
			oldname = fds[s.Args["dfd"]]
		}
		Open(analysis, s.Ret, oldname)
	},
	"rmdir": func(analysis *Analysis, s subject.Syscall) {
		DeleteDir(analysis, s.PID, s.Args["pathname"])
	},
	"close": func(analysis *Analysis, s subject.Syscall) {
		Close(analysis, s.PID, s.Args["fd"])
	},
	"close_range": func(analysis *Analysis, s subject.Syscall) {
		fd := s.Args["fd"]
		max_fd := s.Args["max_fd"]
		a, _ := strconv.Atoi(fd)
		b, _ := strconv.Atoi(max_fd)
		for a < b {
			Close(analysis, s.PID, strconv.Itoa(a))
			a++
		}
	},
	"dup2": func(analysis *Analysis, s subject.Syscall) {
		Open(analysis, s.Args["newfd"], fds[s.Args["oldfd"]])
	},
	"creat": func(analysis *Analysis, s subject.Syscall) {
		Open(analysis, s.Args["filename"], s.Ret)
	},
	"write": Nope,
	"openat": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["filename"]
		if oldname == "" {
			oldname = fds[s.Args["dfd"]]
		}
		Open(analysis, s.Ret, oldname)
	},
	"truncate": func(analysis *Analysis, s subject.Syscall) {
		UpdateFile(analysis, s.PID, s.Args["path"])
	},
	"chroot": Nope,
	"mknod": func(analysis *Analysis, s subject.Syscall) {
		UpdateFile(analysis, s.PID, s.Args["filename"])
	},
	"mkdir":     Nope,
	"ftruncate": Nope,
	"renameat2": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["oldname"]
		newname := s.Args["newname"]
		if oldname == "" {
			oldname = fds[s.Args["olddfd"]]
		}
		if newname == "" {
			newname = fds[s.Args["newdfd"]]
		}
		RenameFile(analysis, s.PID, oldname, newname)
	},
	"fchownat": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["filename"]
		if oldname == "" {
			oldname = fds[s.Args["dfd"]]
		}
		UpdateFile(analysis, s.PID, oldname)
	},
	"mq_unlink": Nope,
	"pwritev":   Nope,
	"unlink": func(analysis *Analysis, s subject.Syscall) {
		DeleteDir(analysis, s.PID, s.Args["pathname"])
	},
	"pwrite64": Nope,
	"pwrite2":  Nope,
	"symlink":  Nope,
	"unlinkat": func(analysis *Analysis, s subject.Syscall) {
		oldname := s.Args["pathname"]
		if oldname == "" {
			oldname = fds[s.Args["dfd"]]
		}
		DeleteDir(analysis, s.PID, oldname)
	},
	"fchown": Nope,
	"linkat": Nope,
	"tkill": func(analysis *Analysis, s subject.Syscall) {
		DeleteProcess(analysis, s.Args["pid"])
	},
	"kill": func(analysis *Analysis, s subject.Syscall) {
		DeleteProcess(analysis, s.Args["pid"])
	},
	"clone": func(analysis *Analysis, s subject.Syscall) {
		NewProcess(analysis, s.Ret)
	},
	"execve":   Nope,
	"execveat": Nope,
	"fork": func(analysis *Analysis, s subject.Syscall) {
		NewProcess(analysis, s.Ret)
	},
	"vfork": func(analysis *Analysis, s subject.Syscall) {
		NewProcess(analysis, s.Ret)
	},
	"tgkill": func(analysis *Analysis, s subject.Syscall) {
		DeleteProcess(analysis, s.Args["pid"])
	},
	"clone3": func(analysis *Analysis, s subject.Syscall) {
		NewProcess(analysis, s.Ret)
	},
	"sethostname":   Nope,
	"setdomainname": Nope,
	"sysinfo":       Nope,
	"fchdir": func(analysis *Analysis, s subject.Syscall) {
		pidpath.SetPidPath(s.PID, fds[s.Args["fd"]])
	},
	"chdir": func(analysis *Analysis, s subject.Syscall) {
		pidpath.SetPidPath(s.PID, fds[s.Args["filename"]])
	},
}
