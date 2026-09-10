package models

type RoutingPoint struct {
	Latitude  float64 `json:"latitude" binding:"gte=-90,lte=90"`
	Longitude float64 `json:"longitude" binding:"gte=-180,lte=180"`
}

type RoutingVehicleConstraints struct {
	HeightMeters       *float64 `json:"height_meters,omitempty" binding:"omitempty,gt=0"`
	WidthMeters        *float64 `json:"width_meters,omitempty" binding:"omitempty,gt=0"`
	LengthMeters       *float64 `json:"length_meters,omitempty" binding:"omitempty,gt=0"`
	WeightTons         *float64 `json:"weight_tons,omitempty" binding:"omitempty,gt=0"`
	AxleLoadTons       *float64 `json:"axle_load_tons,omitempty" binding:"omitempty,gt=0"`
	HazardousMaterials bool     `json:"hazardous_materials"`
}

type RoutingOptions struct {
	TravelMode   string                     `json:"travel_mode,omitempty" binding:"omitempty,oneof=auto truck bicycle pedestrian"`
	DepartureAt  string                     `json:"departure_at,omitempty"`
	Alternatives bool                       `json:"alternatives"`
	Vehicle      *RoutingVehicleConstraints `json:"vehicle,omitempty"`
}

type BuildRouteRequest struct {
	Origin      RoutingPoint   `json:"origin" binding:"required"`
	Destination RoutingPoint   `json:"destination" binding:"required"`
	Waypoints   []RoutingPoint `json:"waypoints,omitempty"`
	Options     RoutingOptions `json:"options"`
}

type BuildMatrixRequest struct {
	Sources []RoutingPoint `json:"sources" binding:"required,min=1,max=100,dive"`
	Targets []RoutingPoint `json:"targets" binding:"required,min=1,max=100,dive"`
	Options RoutingOptions `json:"options"`
}

type RoutingCandidate struct {
	BrigadeID string       `json:"brigade_id" binding:"required,uuid"`
	Location  RoutingPoint `json:"location" binding:"required"`
}

type RankCandidatesRequest struct {
	Destination RoutingPoint       `json:"destination" binding:"required"`
	Candidates  []RoutingCandidate `json:"candidates" binding:"required,min=1,dive"`
	Options     RoutingOptions     `json:"options"`
	Limit       int32              `json:"limit,omitempty" binding:"omitempty,min=1,max=100"`
}

type CreateRoutingRouteRequest struct {
	TicketID    string         `json:"ticket_id" binding:"required,uuid"`
	BrigadeID   string         `json:"brigade_id" binding:"required,uuid"`
	Origin      RoutingPoint   `json:"origin" binding:"required"`
	Destination RoutingPoint   `json:"destination" binding:"required"`
	Waypoints   []RoutingPoint `json:"waypoints,omitempty"`
	Options     RoutingOptions `json:"options"`
}

type GetRoutingRouteRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}

type RecalculateRoutingRouteRequest struct {
	ID              string       `json:"id" binding:"required,uuid"`
	CurrentPosition RoutingPoint `json:"current_position" binding:"required"`
}

type SetRoutingRouteStatusRequest struct {
	ID     string `json:"id" binding:"required,uuid"`
	Status string `json:"status" binding:"required,oneof=ACTIVE COMPLETED CANCELLED"`
}

type ListRoutingRoutesRequest struct {
	TicketID  *string `json:"ticket_id,omitempty" binding:"omitempty,uuid"`
	BrigadeID *string `json:"brigade_id,omitempty" binding:"omitempty,uuid"`
	Status    *string `json:"status,omitempty" binding:"omitempty,oneof=PLANNED ACTIVE COMPLETED CANCELLED"`
	Limit     int32   `json:"limit,omitempty" binding:"omitempty,min=1,max=500"`
	Offset    int32   `json:"offset,omitempty" binding:"omitempty,min=0"`
}
