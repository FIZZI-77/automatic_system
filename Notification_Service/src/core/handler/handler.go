package handler

import (
	"context"
	"errors"
	notificationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/notification/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"notification/models"
	"notification/src/core/service"
	"strings"
)

type Handler struct {
	notificationv1.UnimplementedNotificationServiceServer
	s *service.Service
}

func New(s *service.Service) *Handler { return &Handler{s: s} }
func (h *Handler) ListNotifications(c context.Context, q *notificationv1.ListNotificationsRequest) (*notificationv1.ListNotificationsResponse, error) {
	u, e := self(c, q.GetUserId())
	if e != nil {
		return nil, e
	}
	items, total, unread, e := h.s.List(c, u, q.UnreadOnly, q.GetLimit(), q.GetOffset())
	out := make([]*notificationv1.Notification, 0, len(items))
	for _, v := range items {
		out = append(out, note(v))
	}
	return &notificationv1.ListNotificationsResponse{Notifications: out, Total: total, Unread: unread}, mapped(e)
}
func (h *Handler) MarkRead(c context.Context, q *notificationv1.MarkReadRequest) (*notificationv1.NotificationResponse, error) {
	u, e := self(c, q.GetUserId())
	if e != nil {
		return nil, e
	}
	id, e := parse(q.GetNotificationId())
	if e != nil {
		return nil, e
	}
	v, e := h.s.MarkRead(c, u, id)
	return &notificationv1.NotificationResponse{Notification: note(v)}, mapped(e)
}
func (h *Handler) MarkAllRead(c context.Context, q *notificationv1.MarkAllReadRequest) (*notificationv1.MarkAllReadResponse, error) {
	u, e := self(c, q.GetUserId())
	if e != nil {
		return nil, e
	}
	n, e := h.s.MarkAllRead(c, u)
	return &notificationv1.MarkAllReadResponse{Updated: n}, mapped(e)
}
func (h *Handler) GetPreferences(c context.Context, q *notificationv1.GetPreferencesRequest) (*notificationv1.PreferencesResponse, error) {
	u, e := self(c, q.GetUserId())
	if e != nil {
		return nil, e
	}
	v, e := h.s.GetPreferences(c, u)
	return &notificationv1.PreferencesResponse{Preferences: preferences(v)}, mapped(e)
}
func (h *Handler) UpdatePreferences(c context.Context, q *notificationv1.UpdatePreferencesRequest) (*notificationv1.PreferencesResponse, error) {
	u, e := self(c, q.GetUserId())
	if e != nil {
		return nil, e
	}
	v, e := h.s.GetPreferences(c, u)
	if e != nil {
		return nil, mapped(e)
	}
	if q.InAppEnabled != nil {
		v.InApp = q.GetInAppEnabled()
	}
	if q.PushEnabled != nil {
		v.Push = q.GetPushEnabled()
	}
	if q.EmailEnabled != nil {
		v.Email = q.GetEmailEnabled()
	}
	if q.SmsEnabled != nil {
		v.SMS = q.GetSmsEnabled()
	}
	v.EmailAddress = q.Email
	v.Phone = q.Phone
	v, e = h.s.SavePreferences(c, v)
	return &notificationv1.PreferencesResponse{Preferences: preferences(v)}, mapped(e)
}
func (h *Handler) RegisterDevice(c context.Context, q *notificationv1.RegisterDeviceRequest) (*notificationv1.DeviceResponse, error) {
	u, e := self(c, q.GetUserId())
	if e != nil {
		return nil, e
	}
	v, e := h.s.RegisterDevice(c, &models.Device{UserID: u, Token: q.GetToken(), Platform: q.GetPlatform()})
	return &notificationv1.DeviceResponse{Device: device(v)}, mapped(e)
}
func (h *Handler) DeleteDevice(c context.Context, q *notificationv1.DeleteDeviceRequest) (*notificationv1.DeviceResponse, error) {
	u, e := self(c, q.GetUserId())
	if e != nil {
		return nil, e
	}
	id, e := parse(q.GetDeviceId())
	if e != nil {
		return nil, e
	}
	v, e := h.s.DeleteDevice(c, u, id)
	return &notificationv1.DeviceResponse{Device: device(v)}, mapped(e)
}
func (h *Handler) UpsertTemplate(c context.Context, q *notificationv1.UpsertTemplateRequest) (*notificationv1.TemplateResponse, error) {
	if e := admin(c); e != nil {
		return nil, e
	}
	v, e := h.s.UpsertTemplate(c, &models.Template{EventType: q.GetEventType(), Channel: channel(q.GetChannel()), Subject: q.GetSubject(), Body: q.GetBody(), Active: q.GetActive()})
	return &notificationv1.TemplateResponse{Template: template(v)}, mapped(e)
}
func (h *Handler) ListTemplates(c context.Context, q *notificationv1.ListTemplatesRequest) (*notificationv1.ListTemplatesResponse, error) {
	if e := admin(c); e != nil {
		return nil, e
	}
	var ch *string
	if q.Channel != nil {
		v := channel(q.GetChannel())
		ch = &v
	}
	items, total, e := h.s.ListTemplates(c, q.EventType, ch, q.GetLimit(), q.GetOffset())
	out := make([]*notificationv1.Template, 0, len(items))
	for _, v := range items {
		out = append(out, template(v))
	}
	return &notificationv1.ListTemplatesResponse{Templates: out, Total: total}, mapped(e)
}
func (h *Handler) ListDeliveries(c context.Context, q *notificationv1.ListDeliveriesRequest) (*notificationv1.ListDeliveriesResponse, error) {
	if e := admin(c); e != nil {
		return nil, e
	}
	var st, ch *string
	if q.Status != nil {
		v := deliveryStatus(q.GetStatus())
		st = &v
	}
	if q.Channel != nil {
		v := channel(q.GetChannel())
		ch = &v
	}
	items, total, e := h.s.ListDeliveries(c, st, ch, q.GetLimit(), q.GetOffset())
	out := make([]*notificationv1.Delivery, 0, len(items))
	for _, v := range items {
		out = append(out, delivery(v))
	}
	return &notificationv1.ListDeliveriesResponse{Deliveries: out, Total: total}, mapped(e)
}
func note(v *models.Notification) *notificationv1.Notification {
	if v == nil {
		return nil
	}
	x := &notificationv1.Notification{Id: v.ID.String(), UserId: v.UserID.String(), EventType: v.EventType, Title: v.Title, Body: v.Body, Data: v.Data, Read: v.Read, CreatedAt: timestamppb.New(v.CreatedAt)}
	if v.ReadAt != nil {
		x.ReadAt = timestamppb.New(*v.ReadAt)
	}
	return x
}
func preferences(v *models.Preferences) *notificationv1.Preferences {
	if v == nil {
		return nil
	}
	x := &notificationv1.Preferences{UserId: v.UserID.String(), InAppEnabled: v.InApp, PushEnabled: v.Push, EmailEnabled: v.Email, SmsEnabled: v.SMS, UpdatedAt: timestamppb.New(v.UpdatedAt)}
	x.Email = v.EmailAddress
	x.Phone = v.Phone
	return x
}
func device(v *models.Device) *notificationv1.Device {
	if v == nil {
		return nil
	}
	return &notificationv1.Device{Id: v.ID.String(), UserId: v.UserID.String(), Token: v.Token, Platform: v.Platform, Active: v.Active, CreatedAt: timestamppb.New(v.CreatedAt), UpdatedAt: timestamppb.New(v.UpdatedAt)}
}
func template(v *models.Template) *notificationv1.Template {
	if v == nil {
		return nil
	}
	return &notificationv1.Template{Id: v.ID.String(), EventType: v.EventType, Channel: channelProto(v.Channel), Subject: v.Subject, Body: v.Body, Active: v.Active, CreatedAt: timestamppb.New(v.CreatedAt), UpdatedAt: timestamppb.New(v.UpdatedAt)}
}
func delivery(v *models.Delivery) *notificationv1.Delivery {
	if v == nil {
		return nil
	}
	x := &notificationv1.Delivery{Id: v.ID.String(), NotificationId: v.NotificationID.String(), Channel: channelProto(v.Channel), Recipient: v.Recipient, Status: statusProto(v.Status), Attempts: v.Attempts, NextAttemptAt: timestamppb.New(v.NextAttemptAt), CreatedAt: timestamppb.New(v.CreatedAt), UpdatedAt: timestamppb.New(v.UpdatedAt)}
	x.ProviderId = v.ProviderID
	x.LastError = v.LastError
	return x
}
func actor(c context.Context) (uuid.UUID, []string) {
	m, _ := metadata.FromIncomingContext(c)
	id, _ := uuid.Parse(first(m.Get("x-actor-user-id")))
	return id, strings.Split(strings.Join(m.Get("x-actor-roles"), ","), ",")
}
func self(c context.Context, raw string) (uuid.UUID, error) {
	id, roles := actor(c)
	target, e := parse(raw)
	if e != nil {
		return uuid.Nil, e
	}
	if id == target {
		return target, nil
	}
	for _, r := range roles {
		if strings.TrimSpace(strings.ToLower(r)) == "admin" {
			return target, nil
		}
	}
	return uuid.Nil, status.Error(codes.PermissionDenied, "access denied")
}
func admin(c context.Context) error {
	_, rs := actor(c)
	for _, r := range rs {
		if strings.TrimSpace(strings.ToLower(r)) == "admin" {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "admin role required")
}
func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}
func parse(v string) (uuid.UUID, error) {
	id, e := uuid.Parse(v)
	if e != nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, "invalid id")
	}
	return id, nil
}
func mapped(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, service.ErrNotFound) {
		return status.Error(codes.NotFound, e.Error())
	}
	return status.Error(codes.FailedPrecondition, e.Error())
}
func channel(v notificationv1.Channel) string { return strings.TrimPrefix(v.String(), "CHANNEL_") }
func channelProto(v string) notificationv1.Channel {
	return notificationv1.Channel(notificationv1.Channel_value["CHANNEL_"+v])
}
func deliveryStatus(v notificationv1.DeliveryStatus) string {
	return strings.TrimPrefix(v.String(), "DELIVERY_STATUS_")
}
func statusProto(v string) notificationv1.DeliveryStatus {
	return notificationv1.DeliveryStatus(notificationv1.DeliveryStatus_value["DELIVERY_STATUS_"+v])
}
