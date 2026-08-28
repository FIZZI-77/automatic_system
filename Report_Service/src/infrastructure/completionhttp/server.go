package completionhttp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"report/models"
	"report/src/infrastructure/fileclient"
	"report/src/infrastructure/generator"
)

type Server struct {
	files     *fileclient.Client
	generator *generator.Generator
	secret    string
	logger    *zap.Logger
}

func New(files *fileclient.Client, generator *generator.Generator, secret string, logger *zap.Logger) *Server {
	return &Server{files: files, generator: generator, secret: strings.TrimSpace(secret), logger: logger}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /internal/completion-reports", s.create)
	return mux
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	if s.secret == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Report-Internal-Token")), []byte(s.secret)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var input models.CompletionReport
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	result, err := s.Process(r.Context(), input)
	if err != nil {
		s.fail(w, "generate completion report", err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) Process(ctx context.Context, input models.CompletionReport) (models.CompletionReportResult, error) {
	workReportID, ownerID, fileIDs, err := validate(input)
	if err != nil {
		return models.CompletionReportResult{}, err
	}
	for _, fileID := range fileIDs {
		if err := s.files.LinkExisting(ctx, fileID, workReportID, ownerID, input.ActorRoles); err != nil {
			return models.CompletionReportResult{}, err
		}
	}
	images, err := s.files.DownloadImages(ctx, fileIDs, ownerID, input.ActorRoles)
	if err != nil {
		return models.CompletionReportResult{}, err
	}
	artifact, err := s.generator.GenerateCompletion(input, images)
	if err != nil {
		return models.CompletionReportResult{}, err
	}
	fileID, err := s.files.UploadForResource(ctx, "work_report", workReportID, ownerID, input.ActorRoles, artifact)
	if err != nil {
		return models.CompletionReportResult{}, err
	}
	return models.CompletionReportResult{FileID: fileID.String(), Name: artifact.Name}, nil
}

func (s *Server) Compensate(ctx context.Context, input models.CompletionCompensation) error {
	fileID, err := uuid.Parse(input.FileID)
	if err != nil {
		return errors.New("invalid compensation file_id")
	}
	ownerID, err := uuid.Parse(input.RequestedBy)
	if err != nil {
		return errors.New("invalid compensation requested_by")
	}
	return s.files.Delete(ctx, fileID, ownerID, input.ActorRoles)
}

func validate(input models.CompletionReport) (uuid.UUID, uuid.UUID, []uuid.UUID, error) {
	workReportID, err := uuid.Parse(input.WorkReportID)
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, errors.New("invalid work_report_id")
	}
	ownerID, err := uuid.Parse(input.RequestedBy)
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, errors.New("invalid requested_by")
	}
	if strings.TrimSpace(input.Ticket.ID) == "" || strings.TrimSpace(input.Ticket.Address) == "" || strings.TrimSpace(input.Description) == "" {
		return uuid.Nil, uuid.Nil, nil, errors.New("ticket, address and description are required")
	}
	ids := make([]uuid.UUID, 0, len(input.FileIDs))
	for _, raw := range input.FileIDs {
		id, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			return uuid.Nil, uuid.Nil, nil, errors.New("invalid file_id")
		}
		ids = append(ids, id)
	}
	return workReportID, ownerID, ids, nil
}

func (s *Server) fail(w http.ResponseWriter, operation string, err error) {
	if s.logger != nil {
		s.logger.Error(operation, zap.Error(err))
	}
	writeJSON(w, http.StatusBadGateway, map[string]string{"error": operation + " failed"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func HTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second}
}
