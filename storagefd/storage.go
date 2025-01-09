package storagefd

type StorageFD interface {
	Add(pid, fd, name string) bool
	Get(pid, fd string) string
	Delete(pid, fd string) bool
}
