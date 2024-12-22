package sender

import (
	"bytes"
	"client_siem/entity/subject"
	"client_siem/hash"
	"client_siem/hostinfo"
	"client_siem/token"
	"encoding/json"
	"net/http"
	"time"
)

type Message struct {
	Token string
	subject.Message
}

func (m Message) JSON() string {
	b, _ := json.Marshal(m)
	return string(b)
}

type JWTSender struct {
	HostServer string
	methods    map[string]CommandJWT
}

func InitJWTSender(hostServer string) *JWTSender {
	return &JWTSender{HostServer: hostServer,
		methods: map[string]CommandJWT{
			"init_server": CommandJWTPostForm{Address: hostServer},
			"init":        CommandJWTPostForm{Address: hostServer},
			"new":         CommandJWTPostForm{Address: hostServer},
			"update":      CommandJWTUpdate{Address: hostServer},
			"delete":      CommandJWTDelete{Address: hostServer},
		}}
}

func (j *JWTSender) Send(message subject.Message) bool {
	resp, err := j.methods[message.TypeMessage].Command(Message{token.GetToken(), message}.JSON())
	if err != nil {
		return false
	}
	j.parse(resp)

	return resp.StatusCode == 200
}

func InitInitializationMessage(key string, hash hash.Hash) subject.Message {
	hostInfo := hostinfo.GetHostInfo()
	t := time.Now()
	return subject.Message{
		Message:     hash(key + hostInfo.HostName + t.String()),
		TypeMessage: "init_server",
		HostName:    hostInfo.HostName,
		SystemOS:    hostInfo.HostOS,
		HostIP:      hostInfo.IPs,
		Time:        t,
	}
}

func (j *JWTSender) parse(resp *http.Response) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	str := buf.Bytes()
	m := make(map[string]interface{})
	json.Unmarshal(str, &m)
	_, ok := m["token"]
	if ok {
		token.SetToken(m["token"].(string))
	}
}
