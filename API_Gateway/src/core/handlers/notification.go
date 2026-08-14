package handlers

import (
	"gateway/models"
	notificationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/notification/v1"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"net/http"
	"strings"
	"time"
)

type NotificationHandler struct {
	client   notificationv1.NotificationServiceClient
	redis    *redis.Client
	prefix   string
	upgrader websocket.Upgrader
}

func NewNotificationHandler(c notificationv1.NotificationServiceClient, r *redis.Client, p string) *NotificationHandler {
	return &NotificationHandler{client: c, redis: r, prefix: p, upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}}
}
func (h *NotificationHandler) List(c *gin.Context) {
	var v models.NotificationListRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.ListNotifications(dispatchContext(c), &notificationv1.ListNotificationsRequest{UserId: c.GetString("user_id"), UnreadOnly: v.UnreadOnly, Limit: v.Limit, Offset: v.Offset})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *NotificationHandler) MarkRead(c *gin.Context) {
	var v models.NotificationIDRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.MarkRead(dispatchContext(c), &notificationv1.MarkReadRequest{UserId: c.GetString("user_id"), NotificationId: v.NotificationID})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *NotificationHandler) MarkAllRead(c *gin.Context) {
	x, e := h.client.MarkAllRead(dispatchContext(c), &notificationv1.MarkAllReadRequest{UserId: c.GetString("user_id")})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *NotificationHandler) GetPreferences(c *gin.Context) {
	x, e := h.client.GetPreferences(dispatchContext(c), &notificationv1.GetPreferencesRequest{UserId: c.GetString("user_id")})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *NotificationHandler) UpdatePreferences(c *gin.Context) {
	var v models.NotificationPreferencesRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.UpdatePreferences(dispatchContext(c), &notificationv1.UpdatePreferencesRequest{UserId: c.GetString("user_id"), InAppEnabled: v.InAppEnabled, PushEnabled: v.PushEnabled, EmailEnabled: v.EmailEnabled, SmsEnabled: v.SMSEnabled, Email: v.Email, Phone: v.Phone})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *NotificationHandler) RegisterDevice(c *gin.Context) {
	var v models.RegisterDeviceRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.RegisterDevice(dispatchContext(c), &notificationv1.RegisterDeviceRequest{UserId: c.GetString("user_id"), Token: v.Token, Platform: v.Platform})
	dispatchResponse(c, http.StatusCreated, e, x)
}
func (h *NotificationHandler) DeleteDevice(c *gin.Context) {
	var v models.DeleteDeviceRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.DeleteDevice(dispatchContext(c), &notificationv1.DeleteDeviceRequest{UserId: c.GetString("user_id"), DeviceId: v.DeviceID})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *NotificationHandler) UpsertTemplate(c *gin.Context) {
	var v models.UpsertNotificationTemplateRequest
	if !bindJSON(c, &v) {
		return
	}
	x, e := h.client.UpsertTemplate(dispatchContext(c), &notificationv1.UpsertTemplateRequest{EventType: v.EventType, Channel: notificationChannel(v.Channel), Subject: v.Subject, Body: v.Body, Active: v.Active})
	dispatchResponse(c, http.StatusOK, e, x)
}
func (h *NotificationHandler) ListTemplates(c *gin.Context) {
	var v models.ListNotificationTemplatesRequest
	if !bindJSON(c, &v) {
		return
	}
	q := &notificationv1.ListTemplatesRequest{EventType: v.EventType, Limit: v.Limit, Offset: v.Offset}
	if v.Channel != nil {
		x := notificationChannel(*v.Channel)
		q.Channel = &x
	}
	out, e := h.client.ListTemplates(dispatchContext(c), q)
	dispatchResponse(c, http.StatusOK, e, out)
}
func (h *NotificationHandler) ListDeliveries(c *gin.Context) {
	var v models.ListDeliveriesRequest
	if !bindJSON(c, &v) {
		return
	}
	q := &notificationv1.ListDeliveriesRequest{Limit: v.Limit, Offset: v.Offset}
	if v.Channel != nil {
		x := notificationChannel(*v.Channel)
		q.Channel = &x
	}
	if v.Status != nil {
		x := notificationStatus(*v.Status)
		q.Status = &x
	}
	out, e := h.client.ListDeliveries(dispatchContext(c), q)
	dispatchResponse(c, http.StatusOK, e, out)
}
func (h *NotificationHandler) WebSocket(c *gin.Context) {
	conn, e := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if e != nil {
		return
	}
	defer conn.Close()
	sub := h.redis.Subscribe(c.Request.Context(), h.prefix+c.GetString("user_id"))
	defer sub.Close()
	_ = conn.SetReadDeadline(time.Now().Add(24 * time.Hour))
	for {
		select {
		case <-c.Request.Context().Done():
			return
		case msg, ok := <-sub.Channel():
			if !ok {
				return
			}
			if e = conn.WriteMessage(websocket.TextMessage, []byte(msg.Payload)); e != nil {
				return
			}
		}
	}
}
func notificationChannel(v string) notificationv1.Channel {
	return notificationv1.Channel(notificationv1.Channel_value["CHANNEL_"+strings.ToUpper(v)])
}
func notificationStatus(v string) notificationv1.DeliveryStatus {
	return notificationv1.DeliveryStatus(notificationv1.DeliveryStatus_value["DELIVERY_STATUS_"+strings.ToUpper(v)])
}
