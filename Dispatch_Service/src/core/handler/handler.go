package handler

import (
	"context"
	"errors"
	"strings"

	"dispatch/models"
	"dispatch/src/core/service"

	dispatchv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/dispatch/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Handler struct {
	dispatchv1.UnimplementedDispatchServiceServer
	service *service.Service
}

func New(value *service.Service) *Handler { return &Handler{service: value} }

func (h *Handler) RecommendBrigades(ctx context.Context, req *dispatchv1.RecommendBrigadesRequest) (*dispatchv1.RecommendBrigadesResponse, error) {
	if err := authorize(ctx); err != nil { return nil, err }
	ticketID, skills, err := parseInputIDs(req.GetTicketId(), req.GetRequiredSkillIds()); if err != nil { return nil, err }
	items, err := h.service.Recommend(ctx, &models.RecommendInput{TicketID:ticketID,RequiredSkillIDs:skills,Limit:req.GetLimit()}); if err != nil { return nil,mapError(err) }
	result:=make([]*dispatchv1.DispatchCandidate,0,len(items));for _,item:=range items{result=append(result,&dispatchv1.DispatchCandidate{BrigadeId:item.BrigadeID.String(),Rank:item.Rank,DistanceMeters:item.DistanceMeters,EtaSeconds:item.ETASeconds,Reachable:item.Reachable,Latitude:item.Latitude,Longitude:item.Longitude})}
	return &dispatchv1.RecommendBrigadesResponse{Candidates:result},nil
}

func (h *Handler) DispatchTicket(ctx context.Context, req *dispatchv1.DispatchTicketRequest) (*dispatchv1.DispatchTicketResponse, error) {
	if err:=authorize(ctx);err!=nil{return nil,err};ticketID,skills,err:=parseInputIDs(req.GetTicketId(),req.GetRequiredSkillIds());if err!=nil{return nil,err};assignedBy,err:=uuid.Parse(req.GetAssignedBy());if err!=nil{return nil,status.Error(codes.InvalidArgument,"invalid assigned_by")}
	var brigadeID *uuid.UUID;if req.BrigadeId!=nil{value,parseErr:=uuid.Parse(req.GetBrigadeId());if parseErr!=nil{return nil,status.Error(codes.InvalidArgument,"invalid brigade_id")};brigadeID=&value}
	operation,err:=h.service.Dispatch(ctx,&models.DispatchInput{TicketID:ticketID,BrigadeID:brigadeID,RequiredSkillIDs:skills,AssignedBy:assignedBy,CandidateLimit:req.GetCandidateLimit()});if err!=nil{return nil,mapError(err)};return &dispatchv1.DispatchTicketResponse{Operation:toProto(operation)},nil
}

func (h *Handler) GetDispatchOperation(ctx context.Context, req *dispatchv1.GetDispatchOperationRequest) (*dispatchv1.GetDispatchOperationResponse,error){if err:=authorize(ctx);err!=nil{return nil,err};id,err:=uuid.Parse(req.GetId());if err!=nil{return nil,status.Error(codes.InvalidArgument,"invalid id")};operation,err:=h.service.Get(ctx,id);if err!=nil{return nil,mapError(err)};return &dispatchv1.GetDispatchOperationResponse{Operation:toProto(operation)},nil}
func (h *Handler) CancelDispatch(ctx context.Context, req *dispatchv1.CancelDispatchRequest) (*dispatchv1.CancelDispatchResponse,error){if err:=authorize(ctx);err!=nil{return nil,err};id,err:=uuid.Parse(req.GetId());if err!=nil{return nil,status.Error(codes.InvalidArgument,"invalid id")};actor,err:=uuid.Parse(req.GetCancelledBy());if err!=nil{return nil,status.Error(codes.InvalidArgument,"invalid cancelled_by")};operation,err:=h.service.Cancel(ctx,id,actor);if err!=nil{return nil,mapError(err)};return &dispatchv1.CancelDispatchResponse{Operation:toProto(operation)},nil}

func authorize(ctx context.Context) error { md,_:=metadata.FromIncomingContext(ctx);for _,value:=range md.Get("x-actor-roles"){for _,role:=range strings.Split(value,","){if role=strings.TrimSpace(role);role=="admin"||role=="dispatcher"{return nil}}};return status.Error(codes.PermissionDenied,"dispatcher or admin role required") }
func parseInputIDs(ticket string,rawSkills []string)(uuid.UUID,[]uuid.UUID,error){ticketID,err:=uuid.Parse(ticket);if err!=nil{return uuid.Nil,nil,status.Error(codes.InvalidArgument,"invalid ticket_id")};skills:=make([]uuid.UUID,0,len(rawSkills));for _,raw:=range rawSkills{value,parseErr:=uuid.Parse(raw);if parseErr!=nil{return uuid.Nil,nil,status.Error(codes.InvalidArgument,"invalid skill id")};skills=append(skills,value)};return ticketID,skills,nil}
func toProto(value *models.Operation)*dispatchv1.DispatchOperation{if value==nil{return nil};result:=&dispatchv1.DispatchOperation{Id:value.ID.String(),TicketId:value.TicketID.String(),Status:statusToProto(value.Status),RequestedBy:value.RequestedBy.String(),ExpiresAtUnixMs:value.ExpiresAt.UnixMilli(),CreatedAtUnixMs:value.CreatedAt.UnixMilli(),UpdatedAtUnixMs:value.UpdatedAt.UnixMilli()};if value.BrigadeID!=nil{result.BrigadeId=value.BrigadeID.String()};if value.RouteID!=nil{result.RouteId=value.RouteID.String()};if value.FailureReason!=nil{result.FailureReason=*value.FailureReason};return result}
func statusToProto(value models.Status)dispatchv1.DispatchStatus{switch value{case models.StatusPending:return dispatchv1.DispatchStatus_DISPATCH_STATUS_PENDING;case models.StatusReserved:return dispatchv1.DispatchStatus_DISPATCH_STATUS_RESERVED;case models.StatusAssigned:return dispatchv1.DispatchStatus_DISPATCH_STATUS_ASSIGNED;case models.StatusFailed:return dispatchv1.DispatchStatus_DISPATCH_STATUS_FAILED;case models.StatusCancelled:return dispatchv1.DispatchStatus_DISPATCH_STATUS_CANCELLED;case models.StatusExpired:return dispatchv1.DispatchStatus_DISPATCH_STATUS_EXPIRED;default:return dispatchv1.DispatchStatus_DISPATCH_STATUS_UNSPECIFIED}}
func mapError(err error)error{switch{case errors.Is(err,models.ErrInvalidArgument):return status.Error(codes.InvalidArgument,err.Error());case errors.Is(err,models.ErrNotFound):return status.Error(codes.NotFound,err.Error());case errors.Is(err,models.ErrConflict):return status.Error(codes.Aborted,err.Error());case errors.Is(err,models.ErrForbidden):return status.Error(codes.PermissionDenied,err.Error());default:return status.Error(codes.Unavailable,err.Error())}}
