package models

type PreviewDispatchRequest struct {
	TicketID         string   `json:"ticket_id" binding:"required,uuid"`
	RequiredSkillIDs []string `json:"required_skill_ids,omitempty" binding:"omitempty,dive,uuid"`
	Limit            int32    `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
}
type ReserveBrigadeRequest struct {
	TicketID              string   `json:"ticket_id" binding:"required,uuid"`
	BrigadeID             string   `json:"brigade_id" binding:"required,uuid"`
	RequiredSkillIDs      []string `json:"required_skill_ids,omitempty" binding:"omitempty,dive,uuid"`
	RequestedBy           string   `json:"requested_by" binding:"required,uuid"`
	ReservationTTLSeconds *int64   `json:"reservation_ttl_seconds,omitempty" binding:"omitempty,min=15,max=900"`
}
type ConfirmDispatchRequest struct {
	ID              string `json:"id" binding:"required,uuid"`
	ConfirmedBy     string `json:"confirmed_by" binding:"required,uuid"`
	ExpectedVersion int32  `json:"expected_version" binding:"required,min=1"`
}
type AutoDispatchRequest struct {
	TicketID         string   `json:"ticket_id" binding:"required,uuid"`
	RequiredSkillIDs []string `json:"required_skill_ids,omitempty" binding:"omitempty,dive,uuid"`
	RequestedBy      string   `json:"requested_by" binding:"required,uuid"`
	CandidateLimit   int32    `json:"candidate_limit,omitempty" binding:"omitempty,min=1,max=100"`
}
type GetDispatchRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}
type ListDispatchesRequest struct {
	TicketID  *string `json:"ticket_id,omitempty" binding:"omitempty,uuid"`
	BrigadeID *string `json:"brigade_id,omitempty" binding:"omitempty,uuid"`
	Status    *string `json:"status,omitempty" binding:"omitempty,oneof=PENDING RESERVED CONFIRMING ASSIGNED FAILED CANCELLED EXPIRED"`
	Limit     int32   `json:"limit,omitempty" binding:"omitempty,min=1,max=200"`
	Offset    int32   `json:"offset,omitempty" binding:"omitempty,min=0"`
}
type CancelDispatchRequest struct {
	ID              string `json:"id" binding:"required,uuid"`
	CancelledBy     string `json:"cancelled_by" binding:"required,uuid"`
	ExpectedVersion int32  `json:"expected_version" binding:"required,min=1"`
	Reason          string `json:"reason,omitempty" binding:"omitempty,max=1000"`
}
