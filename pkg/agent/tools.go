package agent

import (
	"fmt"

	openai "github.com/sashabaranov/go-openai"
)

// OpenAITools returns function tool definitions for the LLM from Catalog + ToolSchemas.
func OpenAITools() []openai.Tool {
	schemas := ToolSchemas()
	tools := make([]openai.Tool, 0, len(schemas))

	// mission_complete is LLM-only (not in Catalog).
	names := make([]string, 0, len(Catalog())+1)
	for _, t := range Catalog() {
		names = append(names, t.Name)
	}
	names = append(names, "mission_complete")

	for _, name := range names {
		schema, ok := schemas[name]
		if !ok {
			continue
		}
		desc := name
		if tool, ok := LookupTool(name); ok {
			desc = tool.Description
		} else if name == "mission_complete" {
			desc = "Signal that the objective is achieved or cannot proceed"
		}
		tools = append(tools, openai.Tool{
			Type: openai.ToolTypeFunction,
			Function: &openai.FunctionDefinition{
				Name:        name,
				Description: desc,
				Parameters:  schema,
			},
		})
	}
	return tools
}

// SchemaForTool returns the JSON schema for a tool name.
func SchemaForTool(name string) (map[string]any, error) {
	s, ok := ToolSchemas()[name]
	if !ok {
		return nil, fmt.Errorf("no schema for tool %q", name)
	}
	return s, nil
}