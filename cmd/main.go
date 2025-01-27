package main

import "client_siem/service"

func main() {
	program := service.InitProgram("config/config.ini")
	program.Work()
}
