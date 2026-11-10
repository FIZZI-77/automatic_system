package models

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Validate проверяет диапазоны широты [-90, 90] и долготы [-180, 180].
// Ошибка оборачивает ErrInvalidArgument и содержит название поля field.
func (p Point) Validate(field string) error {

	if p.Latitude < -90 || p.Latitude > 90 {
		return fmt.Errorf("%w: %s latitude", ErrInvalidArgument, field)
	}

	if p.Longitude < -180 || p.Longitude > 180 {
		return fmt.Errorf("%w: %s longitude", ErrInvalidArgument, field)
	}

	return nil
}

// Normalize возвращает копию опций с режимом AUTO вместо пустого TravelMode.
// Исходные опции не изменяет; вложенные указатели не копирует.
func (o RouteOptions) Normalize() RouteOptions {

	if o.TravelMode == "" {
		o.TravelMode = TravelModeAuto
	}

	return o
}

// Validate проверяет допустимый режим движения и положительность заданных
// ограничений транспорта. Пустой режим допустим; нарушение даёт ErrInvalidArgument.
func (o RouteOptions) Validate() error {
	switch o.TravelMode {
	case "", TravelModeAuto, TravelModeTruck, TravelModeBicycle, TravelModePedestrian:
	default:
		return fmt.Errorf("%w: travel mode", ErrInvalidArgument)
	}

	if o.Vehicle != nil {
		values := []*float64{
			o.Vehicle.HeightMeters,
			o.Vehicle.WidthMeters,
			o.Vehicle.LengthMeters,
			o.Vehicle.WeightTons,
			o.Vehicle.AxleLoadTons,
		}
		for _, value := range values {

			if value != nil && *value <= 0 {
				return fmt.Errorf("%w: vehicle constraint", ErrInvalidArgument)
			}

		}
	}

	return nil
}

// Validate проверяет ненулевой запрос, координаты начала, конца, промежуточных
// точек и опции маршрута. Возвращает первую ошибку без изменения in.
func (in *BuildRouteInput) Validate() error {

	if in == nil {
		return fmt.Errorf("%w: request", ErrInvalidArgument)
	}

	if err := in.Origin.Validate("origin"); err != nil {
		return err
	}

	if err := in.Destination.Validate("destination"); err != nil {
		return err
	}

	for _, point := range in.Waypoints {

		if err := point.Validate("waypoint"); err != nil {
			return err
		}

	}
	return in.Options.Validate()
}

// Validate требует от 1 до 100 источников и целей, проверяет их координаты
// и опции. nil запрос и нарушение ограничений дают ErrInvalidArgument.
func (in *BuildMatrixInput) Validate() error {

	if in == nil || len(in.Sources) == 0 || len(in.Targets) == 0 {
		return fmt.Errorf("%w: matrix points", ErrInvalidArgument)
	}

	if len(in.Sources) > 100 || len(in.Targets) > 100 {
		return fmt.Errorf("%w: matrix limit", ErrInvalidArgument)
	}

	for _, point := range in.Sources {

		if err := point.Validate("source"); err != nil {
			return err
		}

	}
	for _, point := range in.Targets {

		if err := point.Validate("target"); err != nil {
			return err
		}

	}
	return in.Options.Validate()
}

// Validate проверяет UUID заявки и бригады, точки и опции маршрута.
// Пробелы вокруг UUID учитывает только при проверке, исходные строки не изменяет.
func (in *CreateRouteInput) Validate() error {

	if in == nil {
		return fmt.Errorf("%w: request", ErrInvalidArgument)
	}

	if _, err := uuid.Parse(strings.TrimSpace(in.TicketID)); err != nil {
		return fmt.Errorf("%w: ticket id", ErrInvalidArgument)
	}

	if _, err := uuid.Parse(strings.TrimSpace(in.BrigadeID)); err != nil {
		return fmt.Errorf("%w: brigade id", ErrInvalidArgument)
	}

	return (&BuildRouteInput{
		Origin:      in.Origin,
		Destination: in.Destination,
		Waypoints:   in.Waypoints,
		Options:     in.Options,
	}).Validate()
}
