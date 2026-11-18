package handlers

import (
	"context"
	"gateway/models"
	notificationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/notification/v1"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"net/http"
	"strings"
	"time"
)

const (
	webSocketPongWait   = 60 * time.Second
	webSocketPingPeriod = 30 * time.Second
	webSocketWriteWait  = 10 * time.Second
)

type NotificationHandler struct {
	client   notificationv1.NotificationServiceClient
	redis    *redis.Client
	prefix   string
	upgrader websocket.Upgrader
}

// NewNotificationHandler создаёт обработчик уведомлений с gRPC-клиентом,
// Redis и префиксом каналов; WebSocket-upgrader разрешает любой Origin.
func NewNotificationHandler(c notificationv1.NotificationServiceClient, r *redis.Client, p string) *NotificationHandler {
	return &NotificationHandler{
		client:   c,
		redis:    r,
		prefix:   p,
		upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }},
	}
}

// List разбирает JSON фильтра прочтения и пагинации и запрашивает уведомления
// пользователя из контекста; при успехе возвращает HTTP 200 через dispatchResponse.
func (h *NotificationHandler) List(c *gin.Context) {
	var v models.NotificationListRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.ListNotifications(dispatchContext(c), &notificationv1.ListNotificationsRequest{UserId: c.GetString("user_id"), UnreadOnly: v.UnreadOnly, Limit: v.Limit, Offset: v.Offset})
	dispatchResponse(c, http.StatusOK, e, x)
}

// MarkRead разбирает ID уведомления из JSON и передаёт отметку прочтения
// для пользователя из контекста сервису; при успехе возвращает HTTP 200.
func (h *NotificationHandler) MarkRead(c *gin.Context) {
	var v models.NotificationIDRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.MarkRead(dispatchContext(c), &notificationv1.MarkReadRequest{UserId: c.GetString("user_id"), NotificationId: v.NotificationID})
	dispatchResponse(c, http.StatusOK, e, x)
}

// MarkAllRead без разбора тела отмечает уведомления текущего пользователя
// прочитанными через сервис; успешный ответ получает HTTP 200.
func (h *NotificationHandler) MarkAllRead(c *gin.Context) {
	x, e := h.client.MarkAllRead(dispatchContext(c), &notificationv1.MarkAllReadRequest{UserId: c.GetString("user_id")})
	dispatchResponse(c, http.StatusOK, e, x)
}

// GetPreferences без разбора тела запрашивает настройки уведомлений пользователя
// из контекста и возвращает HTTP 200 при успехе.
func (h *NotificationHandler) GetPreferences(c *gin.Context) {
	x, e := h.client.GetPreferences(dispatchContext(c), &notificationv1.GetPreferencesRequest{UserId: c.GetString("user_id")})
	dispatchResponse(c, http.StatusOK, e, x)
}

// UpdatePreferences сохраняет необязательность настроек каналов и контактов
// из JSON и передаёт изменение для текущего пользователя сервису; успех даёт HTTP 200.
func (h *NotificationHandler) UpdatePreferences(c *gin.Context) {
	var v models.NotificationPreferencesRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.UpdatePreferences(dispatchContext(c), &notificationv1.UpdatePreferencesRequest{
		UserId:       c.GetString("user_id"),
		InAppEnabled: v.InAppEnabled,
		PushEnabled:  v.PushEnabled,
		EmailEnabled: v.EmailEnabled,
		SmsEnabled:   v.SMSEnabled,
		Email:        v.Email,
		Phone:        v.Phone,
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// RegisterDevice передаёт токен и платформу из JSON и пользователя из контекста
// сервису регистрации устройства; успешный ответ получает HTTP 201.
func (h *NotificationHandler) RegisterDevice(c *gin.Context) {
	var v models.RegisterDeviceRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.RegisterDevice(dispatchContext(c), &notificationv1.RegisterDeviceRequest{UserId: c.GetString("user_id"), Token: v.Token, Platform: v.Platform})
	dispatchResponse(c, http.StatusCreated, e, x)
}

// DeleteDevice разбирает ID устройства из JSON и передаёт удаление для текущего
// пользователя сервису; успешный ответ получает HTTP 200.
func (h *NotificationHandler) DeleteDevice(c *gin.Context) {
	var v models.DeleteDeviceRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.DeleteDevice(dispatchContext(c), &notificationv1.DeleteDeviceRequest{UserId: c.GetString("user_id"), DeviceId: v.DeviceID})
	dispatchResponse(c, http.StatusOK, e, x)
}

// UpsertTemplate преобразует канал и поля шаблона из JSON и вызывает сохранение
// с метаданными пользователя; административную роль проверяет сервис, успех даёт HTTP 200.
func (h *NotificationHandler) UpsertTemplate(c *gin.Context) {
	var v models.UpsertNotificationTemplateRequest

	if !bindJSON(c, &v) {
		return
	}

	x, e := h.client.UpsertTemplate(dispatchContext(c), &notificationv1.UpsertTemplateRequest{
		EventType: v.EventType,
		Channel:   notificationChannel(v.Channel),
		Subject:   v.Subject,
		Body:      v.Body,
		Active:    v.Active,
	})
	dispatchResponse(c, http.StatusOK, e, x)
}

// ListTemplates преобразует необязательный канал, передаёт тип события и пагинацию
// сервису с метаданными пользователя; успешный ответ получает HTTP 200.
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

// ListDeliveries преобразует необязательные канал и статус из JSON и передаёт
// пагинацию сервису; проверку административной роли выполняет сервис.
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

// WebSocket повышает HTTP-соединение и пересылает payload Redis-канала prefix+user_id
// текстовыми сообщениями. Отправляет ping каждые 30 секунд, ждёт pong до 60 секунд
// и ограничивает запись 10 секундами; при отмене или ошибке закрывает подписку и соединение.
// Пользователя берёт из контекста авторизации; Origin допускается настройкой upgrader.
func (h *NotificationHandler) WebSocket(c *gin.Context) {
	conn, e := h.upgrader.Upgrade(c.Writer, c.Request, nil)

	if e != nil {
		return
	}

	defer conn.Close()
	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()
	sub := h.redis.Subscribe(ctx, h.prefix+c.GetString("user_id"))
	defer sub.Close()

	if e = conn.SetReadDeadline(time.Now().Add(webSocketPongWait)); e != nil {
		return
	}

	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(webSocketPongWait))
	})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {

			if _, _, readErr := conn.ReadMessage(); readErr != nil {
				cancel()
				return
			}

		}
	}()
	ping := time.NewTicker(webSocketPingPeriod)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-readDone:
			return
		case <-ping.C:

			if e = conn.SetWriteDeadline(time.Now().Add(webSocketWriteWait)); e != nil {
				return
			}

			if e = conn.WriteMessage(websocket.PingMessage, nil); e != nil {
				return
			}

		case msg, ok := <-sub.Channel():

			if !ok {
				return
			}

			if e = conn.SetWriteDeadline(time.Now().Add(webSocketWriteWait)); e != nil {
				return
			}

			if e = conn.WriteMessage(websocket.TextMessage, []byte(msg.Payload)); e != nil {
				return
			}

		}
	}
}

// notificationChannel преобразует имя канала без учёта регистра;
// неизвестное имя даёт нулевой enum, пробелы не обрезаются.
func notificationChannel(v string) notificationv1.Channel {
	return notificationv1.Channel(notificationv1.Channel_value["CHANNEL_"+strings.ToUpper(v)])
}

// notificationStatus преобразует имя статуса доставки без учёта регистра;
// неизвестное имя даёт нулевой enum, пробелы не обрезаются.
func notificationStatus(v string) notificationv1.DeliveryStatus {
	return notificationv1.DeliveryStatus(notificationv1.DeliveryStatus_value["DELIVERY_STATUS_"+strings.ToUpper(v)])
}
