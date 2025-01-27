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

func (processDriver ProcessDriver) GetSubjects() []subject.Subject {
	procs := GetProcesses()
	processes := make([]subject.Subject, len(procs))
	for i, proc := range procs {
		processes[i] = proc
	}
	return processes
}

func GetProcesses() []subject.Process {
	procs, err := process.Processes()
	processes := make([]subject.Process, len(procs))
	if err != nil {
		return processes
	}
	for i, proc := range procs {
		processes[i] = ProcessToEntity(proc)
	}

	return processes
}

func ProcessToEntity(proc *process.Process) subject.Process {
	username, _ := proc.Username()
	u, err := user.Lookup(username)
	uid := "0"
	if err == nil {
		uid = u.Uid
	}
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
		UID:           uid,
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
