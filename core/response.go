package core

import (
	"encoding/json"
	"fmt"
	"os"
)

type Response struct {
	Status  string      `json:"status"`            // "ok", "error", "info"
	Command string      `json:"command"`            // command that produced this
	Message string      `json:"message,omitempty"`  // human-readable message
	Data    interface{} `json:"data,omitempty"`     // structured payload for AI consumption
}

type OutputMode int

const (
	OutputHuman OutputMode = iota
	OutputJSON
)

func emit(mode OutputMode, r Response) {
	if mode == OutputJSON {
		b, _ := json.Marshal(r)
		fmt.Println(string(b))
		return
	}
	// Human mode
	if r.Message != "" {
		fmt.Println(r.Message)
	}
}

func emitError(mode OutputMode, command, msg string) {
	emit(mode, Response{Status: "error", Command: command, Message: "> " + msg})
}

func emitFatal(mode OutputMode, command, msg string) {
	emit(mode, Response{Status: "error", Command: command, Message: msg})
	os.Exit(1)
}
