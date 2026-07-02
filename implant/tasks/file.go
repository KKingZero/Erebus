package tasks

import (
	"context"
	"fmt"
	"io"
	"os"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"google.golang.org/protobuf/proto"
)

const maxFileSize = 50 << 20 // 50 MB

func executeFileDownload(_ context.Context, data []byte) ([]byte, error) {
	task := &pb.FileDownloadTask{}
	if err := proto.Unmarshal(data, task); err != nil {
		return nil, fmt.Errorf("unmarshal file download task: %w", err)
	}

	resolved, err := resolveJailedPath(task.RemotePath)
	if err != nil {
		return nil, err
	}

	// Open file first, then stat on the same fd to avoid TOCTOU race
	f, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", task.RemotePath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", task.RemotePath, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", task.RemotePath)
	}
	if info.Size() > maxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes (max %d)", info.Size(), maxFileSize)
	}

	content, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", task.RemotePath, err)
	}
	if int64(len(content)) > maxFileSize {
		return nil, fmt.Errorf("file too large (grew during read)")
	}

	result := &pb.FileDownloadResult{
		Filename: info.Name(),
		Data:     content,
	}
	return proto.Marshal(result)
}

func executeFileUpload(_ context.Context, data []byte) ([]byte, error) {
	task := &pb.FileUploadTask{}
	if err := proto.Unmarshal(data, task); err != nil {
		return nil, fmt.Errorf("unmarshal file upload task: %w", err)
	}

	resolved, err := resolveJailedPath(task.RemotePath)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(resolved, task.Data, 0600); err != nil {
		return nil, fmt.Errorf("write %s: %w", task.RemotePath, err)
	}

	result := &pb.FileUploadResult{Success: true}
	return proto.Marshal(result)
}
