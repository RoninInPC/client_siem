package drivers

import (
	"client_siem/entity/subject"
	"os"
	"path/filepath"
)

type FileDriver struct {
	Path string
}

func (fileDriver FileDriver) GetSubjects() []subject.Subject {
	files := fileSystemCopy(fileDriver.Path)
	subjects := make([]subject.Subject, len(files))
	for i, file := range files {
		subjects[i] = file
	}
	return subjects
}

func fileSystemCopy(path string) []subject.File {

	files := make([]subject.File, 0)

	filepath.Walk(path, func(wPath string, info os.FileInfo, err error) error {

		// Обход директории без вывода
		if wPath == path {
			return nil
		}
		if info == nil {
			return err
		}

		// Выводится название файла
		if wPath != path {
			if !info.IsDir() {
				f, err := os.Open(wPath)
				if err != nil {
					return err
				}
				fi, err := f.Stat()
				//bytes, err := os.ReadFile(wPath)
				if err != nil {
					return err
				}
				files = append(files, subject.File{
					FullName: wPath,
					//Content:  bytes,
					Size:     fi.Size(),
					Mode:     fi.Mode().String(),
					Modified: fi.ModTime()})
			}
		}
		return nil
	})
	return files
}

func (fileDriver FileDriver) Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func (fileDriver FileDriver) GetFile(filename string) (subject.File, error) {
	//bytes, _ := os.ReadFile(filename)
	fi, err := os.Stat(filename)
	if err != nil {
		return subject.File{}, err
	}
	return subject.File{
		FullName: filename,
		//Content:  bytes,
		Size:     fi.Size(),
		Mode:     fi.Mode().String(),
		Modified: fi.ModTime()}, nil
}

func (fileDriver FileDriver) FileSystemCopy(channel chan subject.Subject) {
	filepath.Walk(fileDriver.Path, func(wPath string, info os.FileInfo, err error) error {

		// Обход директории без вывода
		if wPath == fileDriver.Path {
			return nil
		}
		if info == nil {
			return err
		}

		// Выводится название файла
		if wPath != fileDriver.Path {
			if !info.IsDir() {
				f, err := os.Open(wPath)
				if err == nil {
					fi, err := f.Stat()
					//bytes, err := os.ReadFile(wPath)
					if err == nil {
						channel <- subject.File{
							FullName: wPath,
							//Content:  bytes,
							Size:     fi.Size(),
							Mode:     fi.Mode().String(),
							Modified: fi.ModTime()}
					}
				}

			}
		}
		return nil
	})
}
