package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"routing/models"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Service struct {
	repo   RouteRepository
	engine RoutingEngine
	log    *zap.Logger
}

// New создаёт сервис маршрутизации с хранилищем и расчётным движком.
// nil logger заменяет журналом без вывода.
func New(
	repo RouteRepository,
	engine RoutingEngine,
	logger *zap.Logger,
) *Service {

	if logger == nil {
		logger = zap.NewNop()
	}

	return &Service{
		repo:   repo,
		engine: engine,
		log:    logger,
	}
}

// BuildRoute проверяет точки и опции, нормализует in.Options и рассчитывает маршрут
// через движок без сохранения. Ошибку расчёта журналирует и возвращает вызывающему коду.
func (s *Service) BuildRoute(
	ctx context.Context,
	in *models.BuildRouteInput,
) (*models.CalculatedRoute, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}

	in.Options = in.Options.Normalize()
	route, err := s.engine.BuildRoute(ctx, in)

	if err != nil {
		s.log.Warn("route calculation failed", zap.Error(err))
		return nil, err
	}

	return route, nil
}

// BuildMatrix проверяет источники, цели и опции, нормализует in.Options
// и возвращает матрицу расстояний, времени и достижимости из движка без сохранения.
func (s *Service) BuildMatrix(
	ctx context.Context,
	in *models.BuildMatrixInput,
) ([]models.MatrixCell, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}

	in.Options = in.Options.Normalize()
	return s.engine.BuildMatrix(ctx, in)
}

// RankCandidates рассчитывает матрицу до точки назначения и стабильно сортирует
// бригады: достижимые первыми, затем по ETA и расстоянию. Положительный Limit
// ограничивает результат; ранги начинаются с 1, недостижимые кандидаты не исключаются.
func (s *Service) RankCandidates(
	ctx context.Context,
	in *models.RankCandidatesInput,
) ([]models.RankedCandidate, error) {

	if in == nil || len(in.Candidates) == 0 {
		return nil, fmt.Errorf("%w: candidates", models.ErrInvalidArgument)
	}

	if err := in.Destination.Validate("destination"); err != nil {
		return nil, err
	}

	sources := make([]models.Point, 0, len(in.Candidates))
	for _, candidate := range in.Candidates {

		if strings.TrimSpace(candidate.BrigadeID) == "" {
			return nil, fmt.Errorf("%w: brigade id", models.ErrInvalidArgument)
		}

		if err := candidate.Location.Validate("candidate location"); err != nil {
			return nil, err
		}

		sources = append(sources, candidate.Location)
	}
	cells, err := s.BuildMatrix(ctx, &models.BuildMatrixInput{
		Sources: sources,
		Targets: []models.Point{in.Destination},
		Options: in.Options,
	})

	if err != nil {
		return nil, err
	}

	ranked := make([]models.RankedCandidate, 0, len(in.Candidates))
	for index, candidate := range in.Candidates {
		value := models.RankedCandidate{Candidate: candidate}
		for _, cell := range cells {

			if cell.SourceIndex == int32(index) && cell.TargetIndex == 0 {
				value.DistanceMeters = cell.DistanceMeters
				value.ETASeconds = cell.DurationSeconds
				value.Reachable = cell.Reachable
				break
			}

		}
		ranked = append(ranked, value)
	}
	sort.SliceStable(ranked, func(i, j int) bool {

		if ranked[i].Reachable != ranked[j].Reachable {
			return ranked[i].Reachable
		}

		if ranked[i].ETASeconds == ranked[j].ETASeconds {
			return ranked[i].DistanceMeters < ranked[j].DistanceMeters
		}

		return ranked[i].ETASeconds < ranked[j].ETASeconds
	})

	if in.Limit > 0 && int(in.Limit) < len(ranked) {
		ranked = ranked[:in.Limit]
	}

	for index := range ranked {
		ranked[index].Rank = int32(index + 1)
	}
	return ranked, nil
}

// CreateRoute проверяет входные данные, рассчитывает и сохраняет маршрут PLANNED
// с ревизией 1. При поддержке поиска открытого маршрута возвращает существующий
// для той же бригады либо ErrConflict для другой. Сбой расчёта записывает в outbox,
// если хранилище поддерживает такую операцию, объединяя ошибки расчёта и записи.
func (s *Service) CreateRoute(
	ctx context.Context,
	in *models.CreateRouteInput,
) (*models.Route, error) {

	if err := in.Validate(); err != nil {
		return nil, err
	}

	if lookup, ok := s.repo.(interface {
		// GetOpenRouteByTicket возвращает открытый маршрут заявки либо ErrNotFound.
		GetOpenRouteByTicket(context.Context, string) (*models.Route, error)
	}); ok {

		if existing, err := lookup.GetOpenRouteByTicket(ctx, in.TicketID); err == nil {

			if existing.BrigadeID != in.BrigadeID {
				return nil, fmt.Errorf("%w: ticket already has an open route", models.ErrConflict)
			}

			return existing, nil
		} else if !errors.Is(err, models.ErrNotFound) {
			return nil, err
		}

	}

	options := in.Options.Normalize()
	calculationStartedAt := time.Now().UTC()
	calculation, err := s.BuildRoute(ctx, &models.BuildRouteInput{
		Origin:      in.Origin,
		Destination: in.Destination,
		Waypoints:   in.Waypoints,
		Options:     options,
	})

	if err != nil {
		finishedAt := time.Now().UTC()
		failure := models.CalculationFailure{
			AggregateType:         "ticket",
			AggregateID:           in.TicketID,
			TicketID:              in.TicketID,
			BrigadeID:             in.BrigadeID,
			Engine:                routingEngineName(s.engine),
			TravelMode:            options.TravelMode,
			FailureCode:           routingFailureCode(err),
			FailureReason:         err.Error(),
			CalculationStartedAt:  calculationStartedAt,
			CalculationFinishedAt: finishedAt,
			CalculationDurationMS: float64(finishedAt.Sub(calculationStartedAt).Microseconds()) / 1000,
		}
		return nil, errors.Join(err, s.recordCalculationFailure(ctx, failure))
	}

	calculationFinishedAt := time.Now().UTC()
	calculationDurationMS := float64(calculationFinishedAt.Sub(calculationStartedAt).Microseconds()) / 1000
	calculationSuccess := true
	now := calculationFinishedAt
	route := &models.Route{
		ID:                        uuid.NewString(),
		TicketID:                  in.TicketID,
		BrigadeID:                 in.BrigadeID,
		Status:                    models.RouteStatusPlanned,
		Origin:                    in.Origin,
		Destination:               in.Destination,
		Waypoints:                 append([]models.Point(nil), in.Waypoints...),
		Options:                   options,
		Calculation:               *calculation,
		Revision:                  1,
		CreatedAt:                 now,
		UpdatedAt:                 now,
		CalculationStartedAt:      &calculationStartedAt,
		CalculationFinishedAt:     &calculationFinishedAt,
		CalculationDurationMillis: &calculationDurationMS,
		CalculationSuccess:        &calculationSuccess,
	}
	return s.repo.CreateRoute(ctx, route)
}

// GetRoute проверяет формат UUID и возвращает сохранённый маршрут по ID.
// Неверный формат даёт ErrInvalidArgument; строку id не нормализует.
func (s *Service) GetRoute(
	ctx context.Context,
	id string,
) (*models.Route, error) {

	if _, err := uuid.Parse(strings.TrimSpace(id)); err != nil {
		return nil, fmt.Errorf("%w: route id", models.ErrInvalidArgument)
	}

	return s.repo.GetRoute(ctx, id)
}

// RecalculateRoute рассчитывает маршрут от текущей позиции к прежней цели
// с сохранёнными промежуточными точками и опциями, увеличивает ревизию и сохраняет расчёт.
// Сбой расчёта пытается записать через необязательную возможность хранилища.
func (s *Service) RecalculateRoute(
	ctx context.Context,
	in *models.RecalculateRouteInput,
) (*models.Route, error) {

	if in == nil {
		return nil, fmt.Errorf("%w: request", models.ErrInvalidArgument)
	}

	if err := in.CurrentPosition.Validate("current position"); err != nil {
		return nil, err
	}

	route, err := s.GetRoute(ctx, in.ID)

	if err != nil {
		return nil, err
	}

	calculationStartedAt := time.Now().UTC()
	calculation, err := s.BuildRoute(ctx, &models.BuildRouteInput{
		Origin:      in.CurrentPosition,
		Destination: route.Destination,
		Waypoints:   route.Waypoints,
		Options:     route.Options,
	})

	if err != nil {
		finishedAt := time.Now().UTC()
		failure := models.CalculationFailure{
			AggregateType:         "route",
			AggregateID:           route.ID,
			TicketID:              route.TicketID,
			BrigadeID:             route.BrigadeID,
			RouteID:               route.ID,
			Engine:                routingEngineName(s.engine),
			TravelMode:            route.Options.TravelMode,
			FailureCode:           routingFailureCode(err),
			FailureReason:         err.Error(),
			CalculationStartedAt:  calculationStartedAt,
			CalculationFinishedAt: finishedAt,
			CalculationDurationMS: float64(finishedAt.Sub(calculationStartedAt).Microseconds()) / 1000,
		}
		return nil, errors.Join(err, s.recordCalculationFailure(ctx, failure))
	}

	calculationFinishedAt := time.Now().UTC()
	calculationDurationMS := float64(calculationFinishedAt.Sub(calculationStartedAt).Microseconds()) / 1000
	calculationSuccess := true
	route.Origin = in.CurrentPosition
	route.Calculation = *calculation
	route.Revision++
	route.UpdatedAt = calculationFinishedAt
	route.CalculationStartedAt = &calculationStartedAt
	route.CalculationFinishedAt = &calculationFinishedAt
	route.CalculationDurationMillis = &calculationDurationMS
	route.CalculationSuccess = &calculationSuccess
	return s.repo.UpdateCalculation(ctx, route)
}

// recordCalculationFailure записывает сбой расчёта, если хранилище поддерживает
// RecordCalculationFailure; иначе возвращает nil без действий.
func (s *Service) recordCalculationFailure(ctx context.Context, failure models.CalculationFailure) error {
	recorder, ok := s.repo.(interface {
		// RecordCalculationFailure сохраняет событие сбоя расчёта в outbox.
		RecordCalculationFailure(context.Context, models.CalculationFailure) error
	})

	if !ok {
		return nil
	}

	return recorder.RecordCalculationFailure(ctx, failure)
}

// routingEngineName возвращает имя движка в нижнем регистре без крайних пробелов.
// Если движок не предоставляет имя или оно пустое, возвращает unknown.
func routingEngineName(engine RoutingEngine) string {
	named, ok := engine.(interface {
		// Name возвращает название расчётного движка.
		Name() string
	})

	if !ok || strings.TrimSpace(named.Name()) == "" {
		return "unknown"
	}

	return strings.ToLower(strings.TrimSpace(named.Name()))
}

// routingFailureCode сопоставляет ошибку тайм-аута, отмены или неверного запроса
// с кодом сбоя расчёта; для прочих ошибок возвращает ENGINE_ERROR.
func routingFailureCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "ENGINE_TIMEOUT"
	case errors.Is(err, context.Canceled):
		return "REQUEST_CANCELED"
	case errors.Is(err, models.ErrInvalidArgument):
		return "INVALID_REQUEST"
	default:
		return "ENGINE_ERROR"
	}
}

// ListRoutes возвращает страницу маршрутов по фильтрам с общим счётчиком.
// nil in заменяет пустым фильтром, неположительный in.Limit — на 50;
// лимит выше 500 и отрицательное смещение отклоняет.
func (s *Service) ListRoutes(
	ctx context.Context,
	in *models.ListRoutesInput,
) (*models.ListRoutesResult, error) {

	if in == nil {
		in = &models.ListRoutesInput{}
	}

	if in.Limit <= 0 {
		in.Limit = 50
	}

	if in.Limit > 500 || in.Offset < 0 {
		return nil, fmt.Errorf("%w: pagination", models.ErrInvalidArgument)
	}

	return s.repo.ListRoutes(ctx, in)
}
