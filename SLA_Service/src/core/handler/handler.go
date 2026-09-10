package handler

import (
	"context"
	"errors"
	slav1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/sla/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"sla/models"
	"sla/src/core/service"
	"strings"
	"time"
)

type Handler struct {
	slav1.UnimplementedSLAServiceServer
	s *service.Service
}

func New(s *service.Service) *Handler { return &Handler{s: s} }
func (h *Handler) CreateRule(c context.Context, q *slav1.CreateRuleRequest) (*slav1.RuleResponse, error) {
	if e := admin(c); e != nil {
		return nil, e
	}
	v, e := ruleFromCreate(q)
	if e != nil {
		return nil, e
	}
	v, e = h.s.CreateRule(c, v)
	return &slav1.RuleResponse{Rule: rule(v)}, mapped(e)
}
func (h *Handler) UpdateRule(c context.Context, q *slav1.UpdateRuleRequest) (*slav1.RuleResponse, error) {
	if e := admin(c); e != nil {
		return nil, e
	}
	id, e := parse(q.GetId())
	if e != nil {
		return nil, e
	}
	v, e := h.s.GetRule(c, id)
	if e != nil {
		return nil, mapped(e)
	}
	if q.Name != nil {
		v.Name = q.GetName()
	}
	if q.DepartmentId != nil {
		v.DepartmentID, e = optionalID(q.GetDepartmentId())
		if e != nil {
			return nil, e
		}
	}
	if q.CategoryId != nil {
		v.CategoryID, e = optionalID(q.GetCategoryId())
		if e != nil {
			return nil, e
		}
	}
	if q.Priority != nil {
		p, ok := priority(q.GetPriority())
		if !ok {
			return nil, bad()
		}
		v.Priority = &p
	}
	if q.ResponseTimeSeconds != nil {
		v.ResponseTime = time.Duration(q.GetResponseTimeSeconds()) * time.Second
	}
	if q.ResolutionTimeSeconds != nil {
		v.ResolutionTime = time.Duration(q.GetResolutionTimeSeconds()) * time.Second
	}
	if q.WarningPercent != nil {
		v.WarningPercent = q.GetWarningPercent()
	}
	if q.Active != nil {
		v.Active = q.GetActive()
	}
	v, e = h.s.UpdateRule(c, v)
	return &slav1.RuleResponse{Rule: rule(v)}, mapped(e)
}
func (h *Handler) DeleteRule(c context.Context, q *slav1.DeleteRuleRequest) (*slav1.RuleResponse, error) {
	if e := admin(c); e != nil {
		return nil, e
	}
	id, e := parse(q.GetId())
	if e != nil {
		return nil, e
	}
	v, e := h.s.DeleteRule(c, id)
	return &slav1.RuleResponse{Rule: rule(v)}, mapped(e)
}
func (h *Handler) GetRule(c context.Context, q *slav1.GetRuleRequest) (*slav1.RuleResponse, error) {
	if e := staff(c); e != nil {
		return nil, e
	}
	id, e := parse(q.GetId())
	if e != nil {
		return nil, e
	}
	v, e := h.s.GetRule(c, id)
	return &slav1.RuleResponse{Rule: rule(v)}, mapped(e)
}
func (h *Handler) ListRules(c context.Context, q *slav1.ListRulesRequest) (*slav1.ListRulesResponse, error) {
	if e := staff(c); e != nil {
		return nil, e
	}
	f := models.RuleFilter{Limit: q.GetLimit(), Offset: q.GetOffset(), Active: q.Active}
	var e error
	if q.DepartmentId != nil {
		f.DepartmentID, e = optionalID(q.GetDepartmentId())
	}
	if e == nil && q.CategoryId != nil {
		f.CategoryID, e = optionalID(q.GetCategoryId())
	}
	if e != nil {
		return nil, e
	}
	if q.Priority != nil {
		p, ok := priority(q.GetPriority())
		if !ok {
			return nil, bad()
		}
		f.Priority = &p
	}
	items, total, e := h.s.ListRules(c, f)
	out := make([]*slav1.SLARule, 0, len(items))
	for _, v := range items {
		out = append(out, rule(v))
	}
	return &slav1.ListRulesResponse{Rules: out, Total: total}, mapped(e)
}
func (h *Handler) GetTicketSLA(c context.Context, q *slav1.GetTicketSLARequest) (*slav1.TicketSLAResponse, error) {
	if e := staff(c); e != nil {
		return nil, e
	}
	id, e := parse(q.GetTicketId())
	if e != nil {
		return nil, e
	}
	v, e := h.s.GetTicketSLA(c, id)
	return &slav1.TicketSLAResponse{Sla: ticketSLA(v)}, mapped(e)
}
func (h *Handler) ListTicketSLAs(c context.Context, q *slav1.ListTicketSLAsRequest) (*slav1.ListTicketSLAsResponse, error) {
	if e := staff(c); e != nil {
		return nil, e
	}
	f := models.SLAFilter{Limit: q.GetLimit(), Offset: q.GetOffset(), Breached: q.Breached}
	var e error
	if q.DepartmentId != nil {
		f.DepartmentID, e = optionalID(q.GetDepartmentId())
	}
	if e != nil {
		return nil, e
	}
	if q.Status != nil {
		s, ok := slaStatus(q.GetStatus())
		if !ok {
			return nil, bad()
		}
		f.Status = &s
	}
	items, total, e := h.s.ListSLAs(c, f)
	out := make([]*slav1.TicketSLA, 0, len(items))
	for _, v := range items {
		out = append(out, ticketSLA(v))
	}
	return &slav1.ListTicketSLAsResponse{Slas: out, Total: total}, mapped(e)
}
func (h *Handler) ListHistory(c context.Context, q *slav1.ListHistoryRequest) (*slav1.ListHistoryResponse, error) {
	if e := staff(c); e != nil {
		return nil, e
	}
	id, e := parse(q.GetTicketId())
	if e != nil {
		return nil, e
	}
	items, total, e := h.s.ListHistory(c, id, q.GetLimit(), q.GetOffset())
	out := make([]*slav1.SLAHistory, 0, len(items))
	for _, v := range items {
		out = append(out, history(v))
	}
	return &slav1.ListHistoryResponse{History: out, Total: total}, mapped(e)
}
func ruleFromCreate(q *slav1.CreateRuleRequest) (*models.Rule, error) {
	v := &models.Rule{Name: q.GetName(), ResponseTime: time.Duration(q.GetResponseTimeSeconds()) * time.Second, ResolutionTime: time.Duration(q.GetResolutionTimeSeconds()) * time.Second, WarningPercent: q.GetWarningPercent()}
	var e error
	if q.DepartmentId != nil {
		v.DepartmentID, e = optionalID(q.GetDepartmentId())
	}
	if e == nil && q.CategoryId != nil {
		v.CategoryID, e = optionalID(q.GetCategoryId())
	}
	if e != nil {
		return nil, e
	}
	if q.Priority != nil {
		p, ok := priority(q.GetPriority())
		if !ok {
			return nil, bad()
		}
		v.Priority = &p
	}
	return v, nil
}
func rule(v *models.Rule) *slav1.SLARule {
	if v == nil {
		return nil
	}
	x := &slav1.SLARule{Id: v.ID.String(), Name: v.Name, ResponseTimeSeconds: int64(v.ResponseTime / time.Second), ResolutionTimeSeconds: int64(v.ResolutionTime / time.Second), WarningPercent: v.WarningPercent, Active: v.Active, CreatedAt: timestamppb.New(v.CreatedAt), UpdatedAt: timestamppb.New(v.UpdatedAt)}
	if v.DepartmentID != nil {
		s := v.DepartmentID.String()
		x.DepartmentId = &s
	}
	if v.CategoryID != nil {
		s := v.CategoryID.String()
		x.CategoryId = &s
	}
	if v.Priority != nil {
		p := priorityProto(*v.Priority)
		x.Priority = &p
	}
	return x
}
func ticketSLA(v *models.TicketSLA) *slav1.TicketSLA {
	if v == nil {
		return nil
	}
	x := &slav1.TicketSLA{Id: v.ID.String(), TicketId: v.TicketID.String(), RuleId: v.RuleID.String(), DepartmentId: v.DepartmentID.String(), CategoryId: v.CategoryID.String(), Priority: priorityProto(v.Priority), Status: statusProto(v.Status), ResponseDeadline: timestamppb.New(v.ResponseDeadline), ResolutionDeadline: timestamppb.New(v.ResolutionDeadline), ResponseBreached: v.ResponseBreached, ResolutionBreached: v.ResolutionBreached, ResponseWarningSent: v.ResponseWarningSent, ResolutionWarningSent: v.ResolutionWarningSent, Version: v.Version, CreatedAt: timestamppb.New(v.CreatedAt), UpdatedAt: timestamppb.New(v.UpdatedAt)}
	if v.RespondedAt != nil {
		x.RespondedAt = timestamppb.New(*v.RespondedAt)
	}
	if v.CompletedAt != nil {
		x.CompletedAt = timestamppb.New(*v.CompletedAt)
	}
	return x
}
func history(v *models.History) *slav1.SLAHistory {
	return &slav1.SLAHistory{Id: v.ID.String(), TicketSlaId: v.TicketSLAID.String(), TicketId: v.TicketID.String(), EventType: eventProto(v.EventType), OccurredAt: timestamppb.New(v.OccurredAt), Details: v.Details}
}
func parse(v string) (uuid.UUID, error) {
	id, e := uuid.Parse(v)
	if e != nil {
		return uuid.Nil, bad()
	}
	return id, nil
}
func optionalID(v string) (*uuid.UUID, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	id, e := parse(v)
	return &id, e
}
func bad() error { return status.Error(codes.InvalidArgument, "invalid request") }
func roles(c context.Context) []string {
	m, _ := metadata.FromIncomingContext(c)
	return strings.Split(strings.Join(m.Get("x-actor-roles"), ","), ",")
}
func admin(c context.Context) error {
	for _, r := range roles(c) {
		if strings.TrimSpace(strings.ToLower(r)) == "admin" {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "admin role required")
}
func staff(c context.Context) error {
	for _, r := range roles(c) {
		r = strings.TrimSpace(strings.ToLower(r))
		if r == "admin" || r == "dispatcher" || r == "worker" {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "staff role required")
}
func mapped(e error) error {
	if e == nil {
		return nil
	}
	switch {
	case errors.Is(e, models.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, e.Error())
	case errors.Is(e, models.ErrNotFound):
		return status.Error(codes.NotFound, e.Error())
	case errors.Is(e, models.ErrConflict):
		return status.Error(codes.AlreadyExists, e.Error())
	default:
		return status.Error(codes.Unavailable, e.Error())
	}
}
func priority(v slav1.TicketPriority) (models.Priority, bool) {
	m := map[slav1.TicketPriority]models.Priority{slav1.TicketPriority_TICKET_PRIORITY_LOW: models.PriorityLow, slav1.TicketPriority_TICKET_PRIORITY_MEDIUM: models.PriorityMedium, slav1.TicketPriority_TICKET_PRIORITY_HIGH: models.PriorityHigh, slav1.TicketPriority_TICKET_PRIORITY_EMERGENCY: models.PriorityEmergency}
	x, ok := m[v]
	return x, ok
}
func priorityProto(v models.Priority) slav1.TicketPriority {
	m := map[models.Priority]slav1.TicketPriority{models.PriorityLow: slav1.TicketPriority_TICKET_PRIORITY_LOW, models.PriorityMedium: slav1.TicketPriority_TICKET_PRIORITY_MEDIUM, models.PriorityHigh: slav1.TicketPriority_TICKET_PRIORITY_HIGH, models.PriorityEmergency: slav1.TicketPriority_TICKET_PRIORITY_EMERGENCY}
	return m[v]
}
func slaStatus(v slav1.SLAStatus) (models.Status, bool) {
	m := map[slav1.SLAStatus]models.Status{slav1.SLAStatus_SLA_STATUS_ACTIVE: models.StatusActive, slav1.SLAStatus_SLA_STATUS_COMPLETED: models.StatusCompleted, slav1.SLAStatus_SLA_STATUS_CANCELLED: models.StatusCancelled}
	x, ok := m[v]
	return x, ok
}
func statusProto(v models.Status) slav1.SLAStatus {
	if v == models.StatusActive {
		return slav1.SLAStatus_SLA_STATUS_ACTIVE
	}
	if v == models.StatusCompleted {
		return slav1.SLAStatus_SLA_STATUS_COMPLETED
	}
	return slav1.SLAStatus_SLA_STATUS_CANCELLED
}
func eventProto(v models.EventType) slav1.SLAEventType {
	return slav1.SLAEventType(slav1.SLAEventType_value["SLA_EVENT_TYPE_"+string(v)])
}
