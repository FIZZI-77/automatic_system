package service

import (
	"context"

	"routing/models"
)

type RoutingEngine interface {
	// BuildRoute рассчитывает маршрут между точками с заданными промежуточными точками и опциями.
	BuildRoute(
		ctx context.Context,
		in *models.BuildRouteInput,
	) (*models.CalculatedRoute, error)
	// BuildMatrix рассчитывает расстояние, время и достижимость для пар источник–цель.
	BuildMatrix(
		ctx context.Context,
		in *models.BuildMatrixInput,
	) ([]models.MatrixCell, error)
}

type RouteRepository interface {
	// CreateRoute сохраняет маршрут и событие создания; конфликт открытого маршрута разрешается по бригаде.
	CreateRoute(
		ctx context.Context,
		route *models.Route,
	) (*models.Route, error)
	// GetRoute возвращает сохранённый маршрут по ID либо ErrNotFound.
	GetRoute(ctx context.Context, id string) (*models.Route, error)
	// UpdateCalculation сохраняет новое начало, расчёт, ревизию и время обновления вместе с событием.
	UpdateCalculation(
		ctx context.Context,
		route *models.Route,
	) (*models.Route, error)
	// UpdateStatus меняет статус при совпадении expectedStatus и записывает событие; иначе даёт ErrConflict.
	UpdateStatus(
		ctx context.Context,
		id string,
		expectedStatus models.RouteStatus,
		status models.RouteStatus,
	) (*models.Route, error)
	// ListRoutes возвращает страницу маршрутов по фильтрам и общее количество совпадений.
	ListRoutes(
		ctx context.Context,
		in *models.ListRoutesInput,
	) (*models.ListRoutesResult, error)
}

type RoutingService interface {
	// BuildRoute проверяет входные данные, нормализует in.Options и рассчитывает маршрут без сохранения.
	BuildRoute(
		ctx context.Context,
		in *models.BuildRouteInput,
	) (*models.CalculatedRoute, error)
	// BuildMatrix проверяет входные точки, нормализует in.Options и рассчитывает матрицу без сохранения.
	BuildMatrix(
		ctx context.Context,
		in *models.BuildMatrixInput,
	) ([]models.MatrixCell, error)
	// RankCandidates ранжирует бригады по достижимости, ETA и расстоянию с ограничением результата Limit.
	RankCandidates(
		ctx context.Context,
		in *models.RankCandidatesInput,
	) ([]models.RankedCandidate, error)
	// CreateRoute рассчитывает и сохраняет маршрут PLANNED либо возвращает открытый маршрут той же бригады.
	CreateRoute(
		ctx context.Context,
		in *models.CreateRouteInput,
	) (*models.Route, error)
	// GetRoute проверяет UUID и возвращает маршрут по ID либо ошибку хранилища.
	GetRoute(ctx context.Context, id string) (*models.Route, error)
	// RecalculateRoute пересчитывает сохранённый маршрут от текущей позиции и увеличивает его ревизию.
	RecalculateRoute(
		ctx context.Context,
		in *models.RecalculateRouteInput,
	) (*models.Route, error)
	// SetRouteStatus применяет допустимый переход статуса с защитой от конкурентного изменения.
	SetRouteStatus(
		ctx context.Context,
		id string,
		status models.RouteStatus,
	) (*models.Route, error)
	// ListRoutes проверяет пагинацию, задаёт in.Limit=50 при неположительном значении и возвращает страницу.
	ListRoutes(
		ctx context.Context,
		in *models.ListRoutesInput,
	) (*models.ListRoutesResult, error)
}
