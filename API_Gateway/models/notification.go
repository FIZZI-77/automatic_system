package models

type NotificationListRequest struct {
	UnreadOnly *bool `json:"unread_only,omitempty"`
	Limit      int32 `json:"limit,omitempty"`
	Offset     int32 `json:"offset,omitempty"`
}
type NotificationIDRequest struct {
	NotificationID string `json:"notification_id" binding:"required,uuid"`
}
type NotificationPreferencesRequest struct {
	InAppEnabled *bool   `json:"in_app_enabled,omitempty"`
	PushEnabled  *bool   `json:"push_enabled,omitempty"`
	EmailEnabled *bool   `json:"email_enabled,omitempty"`
	SMSEnabled   *bool   `json:"sms_enabled,omitempty"`
	Email        *string `json:"email,omitempty"`
	Phone        *string `json:"phone,omitempty"`
}
type RegisterDeviceRequest struct {
	Token    string `json:"token" binding:"required"`
	Platform string `json:"platform" binding:"required"`
}
type DeleteDeviceRequest struct {
	DeviceID string `json:"device_id" binding:"required,uuid"`
}
type UpsertNotificationTemplateRequest struct {
	EventType string `json:"event_type" binding:"required"`
	Channel   string `json:"channel" binding:"required"`
	Subject   string `json:"subject"`
	Body      string `json:"body" binding:"required"`
	Active    bool   `json:"active"`
}
type ListNotificationTemplatesRequest struct {
	EventType *string `json:"event_type,omitempty"`
	Channel   *string `json:"channel,omitempty"`
	Limit     int32   `json:"limit,omitempty"`
	Offset    int32   `json:"offset,omitempty"`
}
type ListDeliveriesRequest struct {
	Status  *string `json:"status,omitempty"`
	Channel *string `json:"channel,omitempty"`
	Limit   int32   `json:"limit,omitempty"`
	Offset  int32   `json:"offset,omitempty"`
}
