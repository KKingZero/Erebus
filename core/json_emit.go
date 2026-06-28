package core

import (
	"encoding/json"
	"fmt"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/agent"
)

// EmitJSONStep prints one agent step as JSON (console -json mode).
func EmitJSONStep(step agent.StepOutput) {
	b, _ := json.Marshal(step)
	fmt.Println(string(b))
}