package scrapper

import (
	"client_siem/entity/subject"
	"fmt"
	gtrace "github.com/RoninInPC/gosyscalltrace"
	"os"
	"os/user"
	"time"
)

type SyscallScrapper struct {
	Bpftrace   *gtrace.Bpftrace
	stopScrape chan bool
}

func InitSyscallScrapper(stopScrape chan bool) SyscallScrapper {
	b := gtrace.NewBpftrace("input.txt", "output.txt")
	pid := os.Getpid()
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "copy_file_range",
		Args: gtrace.Args{
			{gtrace.D, "fd_in", false},
			{gtrace.D, "off_in", false},
			{gtrace.D, "fd_out", false},
			{gtrace.D, "off_out", false},
			{gtrace.D, "len", false},
			{gtrace.D, "flags", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "open",
		Args: gtrace.Args{
			{gtrace.S, "filename", true},
			{gtrace.D, "flags", false},
			{gtrace.D, "mode", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "chmod",
		Args: gtrace.Args{
			{gtrace.S, "filename", true},
			{gtrace.D, "mode", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "chown",
		Args: gtrace.Args{
			{gtrace.S, "filename", true},
			{gtrace.D, "user", false},
			{gtrace.D, "group", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "renameat",
		Args: gtrace.Args{
			{gtrace.D, "olddfd", false},
			{gtrace.S, "oldname", true},
			{gtrace.D, "newdfd", false},
			{gtrace.S, "newname", true},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "dup3",
		Args: gtrace.Args{
			{gtrace.D, "oldfd", false},
			{gtrace.D, "newfd", false},
			{gtrace.D, "flags", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "fchmodat",
		Args: gtrace.Args{
			{gtrace.D, "dfd", false},
			{gtrace.S, "filename", true},
			{gtrace.D, "mode", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "dup",
		Args: gtrace.Args{
			{gtrace.D, "fildes", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "rename",
		Args: gtrace.Args{
			{gtrace.S, "oldname", true},
			{gtrace.S, "newname", true},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "fchmod",
		Args: gtrace.Args{
			{gtrace.D, "fd", false},
			{gtrace.D, "mode", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "openat2",
		Args: gtrace.Args{
			{gtrace.D, "dfd", false},
			{gtrace.S, "filename", true},
			{gtrace.D, "how", false},
			{gtrace.D, "usize", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "rmdir",
		Args: gtrace.Args{
			{gtrace.S, "pathname", true},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "close",
		Args: gtrace.Args{
			{gtrace.D, "fd", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "close_range",
		Args: gtrace.Args{
			{gtrace.D, "fd", false},
			{gtrace.D, "max_fd", false},
			{gtrace.D, "flags", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "dup2",
		Args: gtrace.Args{
			{gtrace.D, "oldfd", false},
			{gtrace.D, "newfd", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "creat",
		Args: gtrace.Args{
			{gtrace.S, "pathname", true},
			{gtrace.D, "mode", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	/*b.AddSyscall(gtrace.Syscall{
		SyscallName: "write",
		Args: gtrace.Args{
			{gtrace.D, "fd", false},
			{gtrace.S, "buf", true},
		},
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})*/
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "openat",
		Args: gtrace.Args{
			{gtrace.D, "dfd", false},
			{gtrace.S, "filename", true},
			{gtrace.D, "flags", false},
			{gtrace.D, "mode", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	/*b.AddSyscall(gtrace.Syscall{
		SyscallName: "truncate",
		Args: gtrace.Args{
			{gtrace.S, "path", true},
			{gtrace.D, "length", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})*/
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "chroot",
		Args: gtrace.Args{
			{gtrace.S, "filename", true},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "mknod",
		Args: gtrace.Args{
			{gtrace.S, "filename", true},
			{gtrace.D, "mode", false},
			{gtrace.D, "dev", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "mkdir",
		Args: gtrace.Args{
			{gtrace.S, "pathname", true},
			{gtrace.D, "mode", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "ftruncate",
		Args: gtrace.Args{
			{gtrace.D, "fd", false},
			{gtrace.D, "length", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "renameat2",
		Args: gtrace.Args{
			{gtrace.D, "olddfd", false},
			{gtrace.S, "oldname", true},
			{gtrace.D, "newdfd", false},
			{gtrace.S, "newname", true},
			{gtrace.D, "flags", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "fchownat",
		Args: gtrace.Args{
			{gtrace.D, "dfd", false},
			{gtrace.S, "filename", true},
			{gtrace.D, "user", false},
			{gtrace.D, "group", false},
			{gtrace.D, "flag", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "mq_unlink",
		Args: gtrace.Args{
			{gtrace.S, "u_name", true},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "pwritev",
		Args: gtrace.Args{
			{gtrace.D, "fd", false},
			{gtrace.S, "vec", true},
			{gtrace.D, "vlen", false},
			{gtrace.D, "pos_l", false},
			{gtrace.D, "pos_h", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "unlink",
		Args: gtrace.Args{
			{gtrace.S, "pathname", true},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "pwrite64",
		Args: gtrace.Args{
			{gtrace.D, "fd", false},
			{gtrace.S, "buf", true},
			{gtrace.D, "count", false},
			{gtrace.D, "pos", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "pwritev2",
		Args: gtrace.Args{
			{gtrace.D, "fd", false},
			{gtrace.S, "vec", true},
			{gtrace.D, "vlen", false},
			{gtrace.D, "pos_l", false},
			{gtrace.D, "pos_h", false},
			{gtrace.D, "flags", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "symlink",
		Args: gtrace.Args{
			{gtrace.S, "oldname", true},
			{gtrace.S, "newname", true},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "unlinkat",
		Args: gtrace.Args{
			{gtrace.D, "dfd", false},
			{gtrace.S, "pathname", true},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "fchown",
		Args: gtrace.Args{
			{gtrace.D, "fd", false},
			{gtrace.D, "user", false},
			{gtrace.D, "group", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "linkat",
		Args: gtrace.Args{
			{gtrace.D, "olddfd", false},
			{gtrace.S, "oldname", true},
			{gtrace.D, "newdfd", false},
			{gtrace.S, "newname", true},
			{gtrace.D, "flags", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "tkill",
		Args: gtrace.Args{
			{gtrace.D, "pid", false},
			{gtrace.D, "sig", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "kill",
		Args: gtrace.Args{
			{gtrace.D, "pid", false},
			{gtrace.D, "sig", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "tgkill",
		Args: gtrace.Args{
			{gtrace.D, "tgid", false},
			{gtrace.D, "pid", false},
			{gtrace.D, "sig", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "clone",
		Args: gtrace.Args{
			{gtrace.D, "clone_flags", false},
			{gtrace.D, "newsp", false},
			{gtrace.D, "parent_tidptr", false},
			{gtrace.D, "child_tidptr", false},
			{gtrace.D, "tls", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "clone3",
		Args: gtrace.Args{
			{gtrace.S, "uargs", true},
			{gtrace.D, "size", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "execve",
		Args: gtrace.Args{
			{gtrace.S, "filename", true},
			{gtrace.S, "argv", true},
			{gtrace.D, "envp", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "execveat",
		Args: gtrace.Args{
			{gtrace.D, "fd", false},
			{gtrace.S, "filename", true},
			{gtrace.S, "argv", true},
			{gtrace.D, "envp", false},
			{gtrace.D, "flags", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName:    "fork",
		Args:           gtrace.Args{},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName:    "vfork",
		Args:           gtrace.Args{},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "sethostname",
		Args: gtrace.Args{
			{gtrace.S, "name", true},
			{gtrace.D, "len", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "setdomainname",
		Args: gtrace.Args{
			{gtrace.S, "name", true},
			{gtrace.D, "len", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	b.AddSyscall(gtrace.Syscall{
		SyscallName: "sysinfo",
		Args: gtrace.Args{
			{gtrace.D, "info", false},
		},
		PID:            pid,
		GetPID:         true,
		GetProcessName: false,
		GetUID:         true,
		GetRet:         false,
		GetTime:        false,
	})
	return SyscallScrapper{Bpftrace: b, stopScrape: stopScrape}
}

func (s SyscallScrapper) Scrape(channel chan subject.Subject, sleep time.Duration) {
	s.stopScrape = make(chan bool)
	s.Bpftrace.Trace()
	go func() {
		for {
			select {
			case <-s.stopScrape:
				close(s.stopScrape)
				return
			default:
				for f := range s.Bpftrace.Events() {
					if f.SyscallName == "" {
						continue
					}
					fmt.Println("    ", f.PID, f.Process, f.Args, f.SyscallName)
					u, err := user.LookupId(f.UID)
					if err != nil {
						if f.UID == "0" {
							channel <- subject.Syscall{TraceInfo: f, Username: "root"}
						} else {
							channel <- subject.Syscall{TraceInfo: f, Username: ""}
						}
					} else {
						channel <- subject.Syscall{TraceInfo: f, Username: u.Username}
					}
				}

			}
		}
	}()
}

func (s SyscallScrapper) Stop() {
	s.stopScrape <- true
}
