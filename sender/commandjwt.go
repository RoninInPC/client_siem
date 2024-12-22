package sender

import (
	"net/http"
	"net/url"
	"strings"
)

type CommandJWT interface {
	Command(string) (*http.Response, error)
}

type CommandJWTPostForm struct {
	Address string
}

func (c CommandJWTPostForm) Command(message string) (*http.Response, error) {
	return http.PostForm(c.Address, url.Values{"json": {message}})
}

type CommandJWTUpdate struct {
	Address string
}

func (c CommandJWTUpdate) Command(message string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPatch, c.Address, strings.NewReader(url.Values{"json": {message}}.Encode()))
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

type CommandJWTDelete struct {
	Address string
}

func (c CommandJWTDelete) Command(message string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, c.Address, strings.NewReader(url.Values{"json": {message}}.Encode()))
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}
