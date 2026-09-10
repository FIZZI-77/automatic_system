package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	filev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/file/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	address := env("FILE_SERVICE_ADDR", "localhost:50059")
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	check(err)
	defer connection.Close()

	client := filev1.NewFileServiceClient(connection)
	testValidation(ctx, client)
	testMetadataMismatch(ctx, client)
	testHappyPath(ctx, client)
}

func testHappyPath(ctx context.Context, client filev1.FileServiceClient) {
	ownerID := uuid.New().String()
	resourceID := uuid.New().String()
	content := []byte("file-service smoke test\n")
	checksum := sha256.Sum256(content)

	created, err := client.CreateUpload(ctx, &filev1.CreateUploadRequest{
		OwnerUserId: ownerID,
		Name:        "smoke.csv",
		ContentType: "text/csv",
		Size:        int64(len(content)),
		Checksum:    base64.StdEncoding.EncodeToString(checksum[:]),
	})
	check(err)
	fileID := created.GetFile().GetId()

	uploadRequest, err := http.NewRequestWithContext(ctx, http.MethodPut, created.GetUploadUrl(), bytes.NewReader(content))
	check(err)
	uploadRequest.Header.Set("Content-Type", "text/csv")
	uploadResponse, err := http.DefaultClient.Do(uploadRequest)
	check(err)
	defer uploadResponse.Body.Close()
	if uploadResponse.StatusCode/100 != 2 {
		body, _ := io.ReadAll(uploadResponse.Body)
		fail("upload failed: %s: %s", uploadResponse.Status, body)
	}

	confirmed, err := client.ConfirmUpload(ctx, &filev1.ConfirmUploadRequest{
		FileId: fileID, ActorUserId: ownerID,
	})
	check(err)
	if confirmed.GetFile().GetStatus() != filev1.FileStatus_FILE_STATUS_UPLOADED {
		fail("unexpected confirmed status: %s", confirmed.GetFile().GetStatus())
	}

	linked, err := client.LinkFile(ctx, &filev1.LinkFileRequest{
		FileId: fileID, ActorUserId: ownerID,
		ResourceType: "ticket_report", ResourceId: resourceID,
	})
	check(err)
	if linked.GetFile().GetStatus() != filev1.FileStatus_FILE_STATUS_LINKED {
		fail("unexpected linked status: %s", linked.GetFile().GetStatus())
	}

	listed, err := client.ListResourceFiles(ctx, &filev1.ListResourceFilesRequest{
		ResourceType: "ticket_report", ResourceId: resourceID,
		ActorUserId: ownerID,
	})
	check(err)
	if len(listed.GetFiles()) != 1 || listed.GetFiles()[0].GetId() != fileID {
		fail("linked file was not returned")
	}
	_, err = client.ListResourceFiles(ctx, &filev1.ListResourceFilesRequest{
		ResourceType: "ticket_report", ResourceId: resourceID,
		ActorUserId: uuid.New().String(),
	})
	if err == nil {
		fail("foreign user unexpectedly listed resource files")
	}

	download, err := client.GetDownloadURL(ctx, &filev1.GetDownloadURLRequest{
		FileId: fileID, ActorUserId: ownerID,
	})
	check(err)
	downloadResponse, err := http.Get(download.GetDownloadUrl())
	check(err)
	defer downloadResponse.Body.Close()
	downloaded, err := io.ReadAll(downloadResponse.Body)
	check(err)
	if !bytes.Equal(downloaded, content) {
		fail("downloaded content differs")
	}

	_, err = client.GetDownloadURL(ctx, &filev1.GetDownloadURLRequest{
		FileId: fileID, ActorUserId: uuid.New().String(),
	})
	if err == nil {
		fail("foreign user unexpectedly received a download URL")
	}

	_, err = client.DeleteFile(ctx, &filev1.DeleteFileRequest{
		FileId: fileID, ActorUserId: ownerID,
	})
	check(err)

	_, err = client.GetDownloadURL(ctx, &filev1.GetDownloadURLRequest{
		FileId: fileID, ActorUserId: ownerID,
	})
	if err == nil {
		fail("deleted file is still accessible")
	}

	fmt.Printf("smoke test passed: file=%s resource=%s bytes=%d\n", fileID, resourceID, len(content))
}

func testValidation(ctx context.Context, client filev1.FileServiceClient) {
	ownerID := uuid.New().String()
	_, err := client.CreateUpload(ctx, &filev1.CreateUploadRequest{
		OwnerUserId: ownerID, Name: "malware.exe", ContentType: "application/x-msdownload", Size: 10,
	})
	if err == nil {
		fail("unsupported content type was accepted")
	}

	_, err = client.CreateUpload(ctx, &filev1.CreateUploadRequest{
		OwnerUserId: ownerID, Name: "large.pdf", ContentType: "application/pdf", Size: 26 << 20,
	})
	if err == nil {
		fail("oversized file was accepted")
	}
}

func testMetadataMismatch(ctx context.Context, client filev1.FileServiceClient) {
	ownerID := uuid.New().String()
	content := []byte("short")
	created, err := client.CreateUpload(ctx, &filev1.CreateUploadRequest{
		OwnerUserId: ownerID, Name: "mismatch.csv", ContentType: "text/csv", Size: int64(len(content) + 1),
	})
	check(err)

	request, err := http.NewRequestWithContext(ctx, http.MethodPut, created.GetUploadUrl(), bytes.NewReader(content))
	check(err)
	request.Header.Set("Content-Type", "text/csv")
	response, err := http.DefaultClient.Do(request)
	check(err)
	response.Body.Close()
	if response.StatusCode/100 != 2 {
		fail("metadata mismatch upload failed unexpectedly: %s", response.Status)
	}

	_, err = client.ConfirmUpload(ctx, &filev1.ConfirmUploadRequest{
		FileId: created.GetFile().GetId(), ActorUserId: ownerID,
	})
	if err == nil {
		fail("metadata mismatch was accepted")
	}
}

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
