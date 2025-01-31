package drivers

import (
	"bufio"
	"client_siem/entity/subject"
	"io"
	"os"
	"os/user"
	"strings"
)

type UserDriver struct {
}

func (userDriver UserDriver) GetSubjects() []subject.Subject {
	users, _ := getUsers()
	subjects := make([]subject.Subject, len(users))
	for i, u := range users {
		subjects[i] = u
	}
	return subjects
}

func getUsers() ([]subject.User, error) {
	var users []subject.User
	file, err := os.Open("/etc/passwd")

	if err != nil {
		return nil, err
	}

	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')

		// skip all line starting with #
		if equal := strings.Index(line, "#"); equal < 0 {
			// get the username and description
			lineSlice := strings.FieldsFunc(line, func(divide rune) bool {
				return divide == ':' // we divide at colon
			})

			if len(lineSlice) > 0 {
				userStr := lineSlice[0]
				usr, err := user.Lookup(userStr)
				if err != nil {
					return nil, err
				}
				users = append(users, UserToEntity(*usr))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return users, nil
}

func (userDriver UserDriver) GetUser(username string) (subject.User, error) {
	user, err := user.Lookup(username)
	if err != nil {
		return subject.User{}, err
	}
	return UserToEntity(*user), nil
}

func UserToEntity(user user.User) subject.User {
	return subject.User{
		Uid:        user.Uid,
		Gid:        user.Gid,
		Username:   user.Username,
		SimpleName: user.Name,
		HomeDir:    user.HomeDir,
	}
}
