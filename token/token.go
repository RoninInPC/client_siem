package token

var (
	token = ""
)

func GetToken() string {
	return token
}

func SetToken(t string) {
	token = t
}
