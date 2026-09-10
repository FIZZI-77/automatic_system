package handler

import (
	"context"
	"errors"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	reportv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/report/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"report/models"
	"report/src/core/repository"
	"report/src/core/service"
)

type Handler struct {
	reportv1.UnimplementedReportServiceServer
	s service.ReportService
}

func New(s service.ReportService) *Handler { return &Handler{s: s} }
func (h *Handler) CreateReport(c context.Context, q *reportv1.CreateReportRequest) (*reportv1.CreateReportResponse, error) {
	owner, e := uuid.Parse(q.RequestedBy)
	if e != nil {
		return nil, bad(e)
	}
	x, e := h.s.Create(c, models.CreateInput{RequestedBy: owner, Name: q.Name, Type: reportType(q.Type), Format: reportFormat(q.Format), Filter: filter(q.Filter), ActorRoles: q.ActorRoles})
	if e != nil {
		return nil, mapErr(e)
	}
	return &reportv1.CreateReportResponse{Report: proto(x)}, nil
}
func (h *Handler) GetReport(c context.Context, q *reportv1.GetReportRequest) (*reportv1.GetReportResponse, error) {
	id, actor, e := ids(q.ReportId, q.ActorUserId)
	if e != nil {
		return nil, bad(e)
	}
	x, e := h.s.Get(c, id, actor, privileged(q.ActorRoles))
	if e != nil {
		return nil, mapErr(e)
	}
	return &reportv1.GetReportResponse{Report: proto(x)}, nil
}
func (h *Handler) ListReports(c context.Context, q *reportv1.ListReportsRequest) (*reportv1.ListReportsResponse, error) {
	actor, e := uuid.Parse(q.ActorUserId)
	if e != nil {
		return nil, bad(e)
	}
	var st *models.Status
	if q.Status != nil {
		x := models.Status(q.Status.String()[14:])
		st = &x
	}
	items, total, e := h.s.List(c, actor, privileged(q.ActorRoles), st, q.Limit, q.Offset)
	if e != nil {
		return nil, mapErr(e)
	}
	out := make([]*reportv1.Report, 0, len(items))
	for _, x := range items {
		out = append(out, proto(x))
	}
	return &reportv1.ListReportsResponse{Reports: out, Total: total}, nil
}
func (h *Handler) CancelReport(c context.Context, q *reportv1.CancelReportRequest) (*reportv1.CancelReportResponse, error) {
	id, a, e := ids(q.ReportId, q.ActorUserId)
	if e != nil {
		return nil, bad(e)
	}
	x, e := h.s.Cancel(c, id, a, privileged(q.ActorRoles))
	if e != nil {
		return nil, mapErr(e)
	}
	return &reportv1.CancelReportResponse{Report: proto(x)}, nil
}
func (h *Handler) RetryReport(c context.Context, q *reportv1.RetryReportRequest) (*reportv1.RetryReportResponse, error) {
	id, a, e := ids(q.ReportId, q.ActorUserId)
	if e != nil {
		return nil, bad(e)
	}
	x, e := h.s.Retry(c, id, a, privileged(q.ActorRoles))
	if e != nil {
		return nil, mapErr(e)
	}
	return &reportv1.RetryReportResponse{Report: proto(x)}, nil
}
func (h *Handler) GetReportDownloadURL(c context.Context, q *reportv1.GetReportDownloadURLRequest) (*reportv1.GetReportDownloadURLResponse, error) {
	id, a, e := ids(q.ReportId, q.ActorUserId)
	if e != nil {
		return nil, bad(e)
	}
	x, e := h.s.Download(c, id, a, q.ActorRoles, privileged(q.ActorRoles))
	if e != nil {
		return nil, mapErr(e)
	}
	return &reportv1.GetReportDownloadURLResponse{Report: proto(x.Report), DownloadUrl: x.URL, ExpiresAt: timestamppb.New(x.ExpiresAt)}, nil
}
func ids(a, b string) (uuid.UUID, uuid.UUID, error) {
	x, e := uuid.Parse(a)
	if e != nil {
		return uuid.Nil, uuid.Nil, e
	}
	y, e := uuid.Parse(b)
	return x, y, e
}
func privileged(r []string) bool {
	for _, x := range r {
		if x == "admin" || x == "dispatcher" {
			return true
		}
	}
	return false
}
func bad(e error) error { return status.Error(codes.InvalidArgument, e.Error()) }
func mapErr(e error) error {
	switch {
	case repository.IsNotFound(e):
		return status.Error(codes.NotFound, "report not found")
	case errors.Is(e, models.ErrForbidden):
		return status.Error(codes.PermissionDenied, e.Error())
	case errors.Is(e, models.ErrInvalidState):
		return status.Error(codes.FailedPrecondition, e.Error())
	default:
		return status.Error(codes.InvalidArgument, e.Error())
	}
}
func reportType(v reportv1.ReportType) models.Type       { return models.Type(v.String()[12:]) }
func reportFormat(v reportv1.ReportFormat) models.Format { return models.Format(v.String()[14:]) }
func filter(v *analyticsv1.AnalyticsFilter) models.Filter {
	if v == nil {
		return models.Filter{}
	}
	x := models.Filter{DepartmentID: v.DepartmentId, CategoryID: v.CategoryId, Priority: v.Priority}
	if v.From != nil {
		z := v.From.AsTime()
		x.From = &z
	}
	if v.To != nil {
		z := v.To.AsTime()
		x.To = &z
	}
	return x
}
func proto(x *models.Report) *reportv1.Report {
	p := &reportv1.Report{Id: x.ID.String(), RequestedBy: x.RequestedBy.String(), Name: x.Name, Type: reportv1.ReportType(reportv1.ReportType_value["REPORT_TYPE_"+string(x.Type)]), Format: reportv1.ReportFormat(reportv1.ReportFormat_value["REPORT_FORMAT_"+string(x.Format)]), Status: reportv1.ReportStatus(reportv1.ReportStatus_value["REPORT_STATUS_"+string(x.Status)]), Filter: &analyticsv1.AnalyticsFilter{DepartmentId: x.Filter.DepartmentID, CategoryId: x.Filter.CategoryID, Priority: x.Filter.Priority}, Attempts: x.Attempts, CreatedAt: timestamppb.New(x.CreatedAt), UpdatedAt: timestamppb.New(x.UpdatedAt)}
	if x.FileID != nil {
		v := x.FileID.String()
		p.FileId = &v
	}
	p.Error = x.Error
	if x.CompletedAt != nil {
		p.CompletedAt = timestamppb.New(*x.CompletedAt)
	}
	if x.Filter.From != nil {
		p.Filter.From = timestamppb.New(*x.Filter.From)
	}
	if x.Filter.To != nil {
		p.Filter.To = timestamppb.New(*x.Filter.To)
	}
	return p
}
