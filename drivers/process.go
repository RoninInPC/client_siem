package drivers

import (
	"client_siem/entity/subject"
	"github.com/shirou/gopsutil/v3/process"
	"os/user"
	"strconv"
	"time"
)

type ProcessDriver struct {
}

func (processDriver ProcessDriver) GetSubjects() []subject.Process {
	return GetProcesses()
}

func GetProcesses() []subject.Process {
	processes := make([]subject.Process, 0)
	procs, err := process.Processes()
	if err != nil {
		return processes
	}
	for _, proc := range procs {
		processes = append(processes, ProcessToEntity(proc))
	}

	return processes
}

func ProcessToEntity(proc *process.Process) subject.Process {
	username, _ := proc.Username()
	u, _ := user.Lookup(username)
	nice, _ := proc.Nice()
	isRunning, _ := proc.IsRunning()
	isBackground, _ := proc.Background()
	createTimeInt, _ := proc.CreateTime()
	statuses, _ := proc.Status()
	name, _ := proc.Name()
	cmdLine, _ := proc.Cmdline()
	percentCPU, _ := proc.CPUPercent()
	percentMemory, _ := proc.MemoryPercent()

	return subject.Process{
		PID:           strconv.Itoa(int(proc.Pid)),
		UID:           u.Uid,
		Nice:          nice,
		IsRunning:     isRunning,
		IsBackGround:  isBackground,
		CreateTime:    time.UnixMilli(createTimeInt),
		Status:        statuses,
		NameProcess:   name,
		CMDLine:       cmdLine,
		PercentCPU:    percentCPU,
		PercentMemory: percentMemory,
	}
}

func (processDriver ProcessDriver) Exists(pid string) bool {
	p, err := strconv.Atoi(pid)
	if err != nil {
		return false
	}
	exists, _ := process.PidExists(int32(p))
	return exists
}

func (processDriver ProcessDriver) GetProcess(pid string) subject.Process {
	p, _ := strconv.Atoi(pid)
	pr, _ := process.NewProcess(int32(p))
	return ProcessToEntity(pr)
}
