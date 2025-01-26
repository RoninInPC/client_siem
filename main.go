package main

import "client_siem/service"

func main() {
	program := service.Init("/config/config.ini")
	program.Work()
}
