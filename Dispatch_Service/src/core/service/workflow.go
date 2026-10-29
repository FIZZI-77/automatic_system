package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"dispatch/models"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	locationv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/location/v1"
	routingv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/routing/v1"
	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Preview подбирает доступные бригады для заявки NEW по ведомству, навыкам и свежим
// координатам, затем ранжирует их через Routing. В in заменяет неположительный Limit
// на 10, отклоняет лимит выше 100; отсутствие кандидатов возвращает как пустой срез.
func (s *Service) Preview(ctx context.Context, in *models.RecommendInput) ([]models.Candidate, error) {

	if in == nil || in.TicketID == uuid.Nil {
		return nil, fmt.Errorf("%w: ticket_id", models.ErrInvalidArgument)
	}

	if in.Limit <= 0 {
		in.Limit = 10
	}

	if in.Limit > 100 {
		return nil, fmt.Errorf("%w: limit must not exceed 100", models.ErrInvalidArgument)
	}

	ctx = forwardMetadata(ctx)

	ticket, err := s.getNewTicket(ctx, in.TicketID)

	if err != nil {
		return nil, err
	}

	available, err := s.deps.Brigades.GetAvailableBrigades(ctx, &brigadev1.GetAvailableBrigadesRequest{
		DepartmentId:     ticket.GetDepartmentId(),
		Longitude:        &ticket.Longitude,
		Latitude:         &ticket.Latitude,
		RequiredSkillIds: uuidStrings(in.RequiredSkillIDs),
		Limit:            max(in.Limit*3, 20),
	})

	if err != nil {
		return nil, fmt.Errorf("get available brigades: %w", err)
	}

	ids := make([]string, 0, len(available.GetBrigades()))
	for _, brigade := range available.GetBrigades() {
		ids = append(ids, brigade.GetId())
	}

	if len(ids) == 0 {
		return []models.Candidate{}, nil
	}

	locations, err := s.deps.Location.GetCurrentLocations(ctx, &locationv1.GetCurrentLocationsRequest{
		BrigadeIds: ids,
		AllowStale: false,
	})

	if err != nil {
		return nil, fmt.Errorf("get brigade locations: %w", err)
	}

	candidates := make([]*routingv1.Candidate, 0, len(ids))
	for _, id := range ids {
		current := locations.GetLocations()[id]

		if current == nil || current.GetPosition() == nil {
			continue
		}

		candidates = append(candidates, &routingv1.Candidate{
			BrigadeId: id,
			Location: &routingv1.Point{
				Latitude:  current.GetPosition().GetLatitude(),
				Longitude: current.GetPosition().GetLongitude(),
			},
		})
	}

	if len(candidates) == 0 {
		return []models.Candidate{}, nil
	}

	ranked, err := s.deps.Routing.RankCandidates(ctx, &routingv1.RankCandidatesRequest{
		Destination: &routingv1.Point{
			Latitude:  ticket.GetLatitude(),
			Longitude: ticket.GetLongitude(),
		},
		Candidates: candidates,
		Options: &routingv1.RouteOptions{
			TravelMode: routingv1.TravelMode_TRAVEL_MODE_AUTO,
		},
		Limit: in.Limit,
	})

	if err != nil {
		return nil, fmt.Errorf("rank candidates: %w", err)
	}

	result := make([]models.Candidate, 0, len(ranked.GetCandidates()))
	for _, item := range ranked.GetCandidates() {
		id, parseErr := uuid.Parse(item.GetBrigadeId())

		if parseErr != nil || item.GetLocation() == nil {
			continue
		}

		result = append(result, models.Candidate{
			BrigadeID:      id,
			Rank:           item.GetRank(),
			DistanceMeters: item.GetDistanceMeters(),
			ETASeconds:     item.GetEtaSeconds(),
			Reachable:      item.GetReachable(),
			Latitude:       item.GetLocation().GetLatitude(),
			Longitude:      item.GetLocation().GetLongitude(),
		})
	}

	return result, nil
}

// Reserve создаёт ручную операцию для заявки NEW и резервирует указанную бригаду
// после проверки её пригодности. TTL берёт из in или настроек сервиса и требует
// диапазон 15 секунд–15 минут; создание операции предшествует внешнему резервированию.
func (s *Service) Reserve(ctx context.Context, in *models.ReserveInput) (*models.Operation, error) {

	if in == nil || in.TicketID == uuid.Nil || in.BrigadeID == uuid.Nil || in.RequestedBy == uuid.Nil {
		return nil, fmt.Errorf("%w: reserve input", models.ErrInvalidArgument)
	}

	ttl := in.TTL

	if ttl <= 0 {
		ttl = s.ttl
	}

	if ttl < 15*time.Second || ttl > 15*time.Minute {
		return nil, fmt.Errorf("%w: reservation TTL must be between 15s and 15m", models.ErrInvalidArgument)
	}

	ctx = forwardMetadata(ctx)
	ticket, err := s.getNewTicket(ctx, in.TicketID)

	if err != nil {
		return nil, err
	}

	createInput, err := operationInput(ticket, in.TicketID, in.RequestedBy, models.ModeManual, ttl)

	if err != nil {
		return nil, err
	}

	op, err := s.repo.Create(ctx, createInput)

	if err != nil {
		return nil, err
	}

	return s.reserveExisting(ctx, op, in.BrigadeID, in.RequiredSkillIDs, in.RequestedBy)
}

// AutoDispatch создаёт или возобновляет автоматическое назначение бригады на заявку.
// TriggerEventID позволяет повторно использовать операцию; неположительный
// CandidateLimit в in заменяется на 10. Продолжение выполняется под блокировкой операции.
func (s *Service) AutoDispatch(ctx context.Context, in *models.AutoInput) (*models.Operation, error) {

	if in == nil || in.TicketID == uuid.Nil || in.RequestedBy == uuid.Nil {
		return nil, fmt.Errorf("%w: auto dispatch input", models.ErrInvalidArgument)
	}

	if in.CandidateLimit <= 0 {
		in.CandidateLimit = 10
	}

	ctx = forwardMetadata(ctx)

	if in.TriggerEventID != nil {
		existing, lookupErr := s.repo.GetByTriggerEvent(ctx, *in.TriggerEventID)

		if lookupErr == nil {
			return s.resumeAutomaticLocked(ctx, existing, in)
		}

		if !errors.Is(lookupErr, models.ErrNotFound) {
			return nil, lookupErr
		}

	}

	ticket, err := s.getNewTicket(ctx, in.TicketID)

	if err != nil {
		return nil, err
	}

	createInput, err := operationInput(ticket, in.TicketID, in.RequestedBy, models.ModeAutomatic, s.ttl)

	if err != nil {
		return nil, err
	}

	createInput.TriggerEventID = in.TriggerEventID
	op, err := s.repo.Create(ctx, createInput)

	if err != nil {
		return nil, err
	}

	return s.resumeAutomaticLocked(ctx, op, in)
}

// resumeAutomaticLocked захватывает блокировку операции и продолжает автоматическое
// назначение. Если операция занята, возвращает переданный op без ожидания;
// ошибку освобождения блокировки записывает в журнал.
func (s *Service) resumeAutomaticLocked(ctx context.Context, op *models.Operation, in *models.AutoInput) (*models.Operation, error) {
	releaseLock, acquired, err := s.repo.TryOperationLock(ctx, op.ID)

	if err != nil {
		return nil, err
	}

	if !acquired {
		return op, nil
	}

	defer func() {

		if releaseErr := releaseLock(); releaseErr != nil {
			s.log.Error("release dispatch operation lock", zap.Error(releaseErr), zap.String("operation_id", op.ID.String()))
		}

	}()
	return s.resumeAutomatic(ctx, op, in)
}

// resumeAutomatic продолжает назначение по статусу op: ранжирует и перебирает
// достижимые бригады, подтверждает резерв либо восстанавливает CONFIRMING.
// Терминальную операцию возвращает без изменений; вызывающий код удерживает её блокировку.
func (s *Service) resumeAutomatic(ctx context.Context, op *models.Operation, in *models.AutoInput) (*models.Operation, error) {
	switch op.Status {
	case models.StatusAssigned, models.StatusFailed, models.StatusCancelled, models.StatusExpired:
		return op, nil
	case models.StatusReserved:
		return s.confirm(ctx, &models.ConfirmInput{
			ID:              op.ID,
			ConfirmedBy:     in.RequestedBy,
			ExpectedVersion: op.Version,
		})
	case models.StatusConfirming:
		return s.finishConfirm(ctx, op, in.RequestedBy)
	case models.StatusPending:
	default:
		return nil, fmt.Errorf("%w: unsupported automatic dispatch status %s", models.ErrConflict, op.Status)
	}
	candidates, err := s.Preview(ctx, &models.RecommendInput{
		TicketID:         in.TicketID,
		RequiredSkillIDs: in.RequiredSkillIDs,
		Limit:            in.CandidateLimit,
	})

	if err != nil {
		_, _ = s.repo.SetFailed(ctx, op.ID, "CANDIDATE_RANKING", "CANDIDATE_RANKING_FAILED", err.Error(), op.Version)
		return nil, err
	}

	reachableCount := 0
	for _, candidate := range candidates {

		if candidate.Reachable {
			reachableCount++
		}

	}

	if err = s.repo.RecordCandidates(ctx, op, len(candidates), reachableCount); err != nil {
		_, _ = s.repo.SetFailed(ctx, op.ID, "EVENT_PERSISTENCE", "CANDIDATE_EVENT_FAILED", err.Error(), op.Version)
		return nil, err
	}

	if len(candidates) == 0 {
		_, _ = s.repo.SetFailed(ctx, op.ID, "CANDIDATE_SELECTION", "NO_REACHABLE_BRIGADE", "no reachable brigade", op.Version)
		return nil, fmt.Errorf("%w: no reachable brigade", models.ErrNotFound)
	}

	lastErr := errors.New("no reachable brigade")
	for _, candidate := range candidates {

		if !candidate.Reachable {
			continue
		}

		reserved, reserveErr := s.reserveExisting(ctx, op, candidate.BrigadeID, in.RequiredSkillIDs, in.RequestedBy)

		if reserveErr != nil {
			lastErr = reserveErr
			continue
		}

		return s.confirm(ctx, &models.ConfirmInput{
			ID:              reserved.ID,
			ConfirmedBy:     in.RequestedBy,
			ExpectedVersion: reserved.Version,
		})
	}
	_, _ = s.repo.SetFailed(ctx, op.ID, "RESERVATION", "RESERVATION_FAILED", lastErr.Error(), op.Version)
	return nil, fmt.Errorf("auto dispatch: %w", lastErr)
}

// Confirm проверяет входные ID и версию, захватывает блокировку операции и запускает
// подтверждение резерва. Занятая операция возвращает ErrConflict.
func (s *Service) Confirm(ctx context.Context, in *models.ConfirmInput) (*models.Operation, error) {

	if in == nil || in.ID == uuid.Nil || in.ConfirmedBy == uuid.Nil || in.ExpectedVersion <= 0 {
		return nil, fmt.Errorf("%w: confirm input", models.ErrInvalidArgument)
	}

	releaseLock, acquired, err := s.repo.TryOperationLock(ctx, in.ID)

	if err != nil {
		return nil, err
	}

	if !acquired {
		return nil, models.ErrConflict
	}

	defer func() {

		if releaseErr := releaseLock(); releaseErr != nil {
			s.log.Error("release dispatch confirmation lock", zap.Error(releaseErr), zap.String("operation_id", in.ID.String()))
		}

	}()
	if _, err := s.Get(ctx, in.ID); err != nil {
		return nil, err
	}
	return s.confirm(ctx, in)
}

// confirm требует RESERVED с версией ExpectedVersion, проверяет заявку NEW,
// получает координаты бригады, создаёт маршрут и сохраняет CONFIRMING перед назначением.
// При сбоях пытается отменить маршрут или освободить резерв; требует внешней блокировки операции.
func (s *Service) confirm(ctx context.Context, in *models.ConfirmInput) (*models.Operation, error) {
	ctx = forwardMetadata(ctx)
	op, err := s.repo.Get(ctx, in.ID)

	if err != nil {
		return nil, err
	}

	if op.Status != models.StatusReserved || op.Version != in.ExpectedVersion || op.BrigadeID == nil {
		return nil, models.ErrConflict
	}

	ticket, err := s.getNewTicket(ctx, op.TicketID)

	if err != nil {
		return s.failAndRelease(ctx, op, in.ConfirmedBy, err)
	}

	location, err := s.deps.Location.GetCurrentLocation(ctx, &locationv1.GetCurrentLocationRequest{
		SubjectType: locationv1.SubjectType_SUBJECT_TYPE_BRIGADE,
		SubjectId:   op.BrigadeID.String(),
	})

	if err != nil || location.GetLocation() == nil || location.GetLocation().GetPosition() == nil {

		if err == nil {
			err = errors.New("brigade location unavailable")
		}

		return s.failAndRelease(ctx, op, in.ConfirmedBy, err)
	}

	position := location.GetLocation().GetPosition()
	route, err := s.deps.Routing.CreateRoute(ctx, &routingv1.CreateRouteRequest{
		TicketId:  op.TicketID.String(),
		BrigadeId: op.BrigadeID.String(),
		Origin: &routingv1.Point{
			Latitude:  position.GetLatitude(),
			Longitude: position.GetLongitude(),
		},
		Destination: &routingv1.Point{
			Latitude:  ticket.GetLatitude(),
			Longitude: ticket.GetLongitude(),
		},
		Options: &routingv1.RouteOptions{
			TravelMode: routingv1.TravelMode_TRAVEL_MODE_AUTO,
		},
	})

	if err != nil || route.GetRoute() == nil {

		if err == nil {
			err = errors.New("routing returned an empty route")
		}

		return s.failAndRelease(ctx, op, in.ConfirmedBy, err)
	}

	routeID, err := uuid.Parse(route.GetRoute().GetId())

	if err != nil {
		s.cancelRoute(ctx, route.GetRoute().GetId())
		return s.failAndRelease(ctx, op, in.ConfirmedBy, err)
	}

	op, err = s.repo.BeginConfirm(ctx, op.ID, routeID, op.Version)

	if err != nil {
		s.cancelRoute(ctx, routeID.String())
		return nil, err
	}

	return s.finishConfirm(ctx, op, in.ConfirmedBy)
}

// finishConfirm назначает бригаду из op заявке и фиксирует ASSIGNED.
// При ошибке назначения принимает уже назначенную ту же бригаду как успех;
// иначе отменяет маршрут и завершает операцию с освобождением резерва.
func (s *Service) finishConfirm(ctx context.Context, op *models.Operation, actor uuid.UUID) (*models.Operation, error) {

	if op.BrigadeID == nil || op.RouteID == nil {
		return nil, fmt.Errorf("%w: confirming dispatch misses brigade or route", models.ErrConflict)
	}

	_, err := s.deps.Tickets.AssignBrigade(ctx, &ticketv1.AssignBrigadeRequest{
		TicketId:   op.TicketID.String(),
		BrigadeId:  op.BrigadeID.String(),
		AssignedBy: actor.String(),
		Comment:    "assigned by dispatch",
	})

	if err != nil {
		ticketResponse, getErr := s.deps.Tickets.GetTicket(ctx, &ticketv1.GetTicketRequest{TicketId: op.TicketID.String()})
		alreadyAssigned := getErr == nil && ticketResponse.GetTicket().GetBrigadeId() == op.BrigadeID.String()

		if !alreadyAssigned {
			s.cancelRoute(ctx, op.RouteID.String())
			return s.failAndRelease(ctx, op, actor, fmt.Errorf("assign ticket: %w", err))
		}

	}

	return s.repo.FinishConfirm(ctx, op.ID, op.Version)
}

// Get возвращает операцию диспетчеризации по ID либо ErrNotFound.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Operation, error) {
	operation, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := authorizeOperation(ctx, operation); err != nil {
		return nil, err
	}
	return operation, nil
}

// List возвращает страницу операций по фильтрам и общее число совпадений.
// nil in заменяет пустым фильтром, неположительный in.Limit — на 50;
// лимит выше 200 и отрицательное смещение отклоняет.
func (s *Service) List(ctx context.Context, in *models.ListInput) ([]*models.Operation, int64, error) {

	if in == nil {
		in = &models.ListInput{}
	}

	if in.Limit <= 0 {
		in.Limit = 50
	}

	if in.Limit > 200 || in.Offset < 0 {
		return nil, 0, fmt.Errorf("%w: pagination", models.ErrInvalidArgument)
	}

	department, err := actorDepartment(ctx)
	if err != nil {
		return nil, 0, err
	}
	scoped := *in
	scoped.DepartmentID = department
	return s.repo.List(ctx, &scoped)
}

// Cancel переводит PENDING или RESERVED с версией ExpectedVersion в CANCELLED,
// затем пытается освободить бригаду. Ошибка освобождения журналируется и не отменяет
// успешный результат; неподходящий статус или версия дают ErrConflict.
func (s *Service) Cancel(ctx context.Context, in *models.CancelInput) (*models.Operation, error) {

	if in == nil || in.ID == uuid.Nil || in.CancelledBy == uuid.Nil || in.ExpectedVersion <= 0 {
		return nil, fmt.Errorf("%w: cancel input", models.ErrInvalidArgument)
	}

	op, err := s.repo.Get(ctx, in.ID)

	if err != nil {
		return nil, err
	}

	if op.Version != in.ExpectedVersion || (op.Status != models.StatusPending && op.Status != models.StatusReserved) {
		return nil, models.ErrConflict
	}
	if err := authorizeOperation(ctx, op); err != nil {
		return nil, err
	}

	reason := in.Reason

	if reason == "" {
		reason = "cancelled by dispatcher"
	}

	cancelled, err := s.repo.SetTerminal(ctx, op.ID, models.StatusCancelled, reason, op.Version)

	if err != nil {
		return nil, err
	}

	if op.BrigadeID != nil {
		_ = s.release(forwardMetadata(ctx), *op.BrigadeID, in.CancelledBy)
	}

	return cancelled, nil
}

// reserveExisting проверяет заявку NEW и пригодность бригады, сохраняет RESERVED
// и устанавливает бригаде BUSY. При сбое внешнего резервирования пытается записать
// FAILED и вернуть бригаду в AVAILABLE, объединяя ошибки этих действий.
func (s *Service) reserveExisting(ctx context.Context, op *models.Operation, brigadeID uuid.UUID, skills []uuid.UUID, actor uuid.UUID) (*models.Operation, error) {
	ticket, err := s.getNewTicket(ctx, op.TicketID)

	if err != nil {
		return nil, err
	}

	check, err := s.deps.Brigades.CheckBrigadeCanHandleTicket(ctx, &brigadev1.CheckBrigadeCanHandleTicketRequest{
		BrigadeId:        brigadeID.String(),
		DepartmentId:     ticket.GetDepartmentId(),
		Longitude:        ticket.GetLongitude(),
		Latitude:         ticket.GetLatitude(),
		RequiredSkillIds: uuidStrings(skills),
	})

	if err != nil {
		return nil, fmt.Errorf("check brigade: %w", err)
	}

	if !check.GetCanHandle() {
		return nil, fmt.Errorf("%w: brigade cannot handle ticket: %v", models.ErrConflict, check.GetReasons())
	}

	reserved, err := s.repo.SetReserved(ctx, op.ID, brigadeID, op.Version)

	if err != nil {
		return nil, err
	}

	_, err = s.deps.Brigades.SetBrigadeStatus(ctx, &brigadev1.SetBrigadeStatusRequest{
		BrigadeId:       brigadeID.String(),
		Status:          brigadev1.BrigadeStatus_BRIGADE_STATUS_BUSY,
		Reason:          "dispatch reservation",
		ChangedByUserId: actor.String(),
	})

	if err != nil {
		_, transitionErr := s.repo.SetFailed(ctx, reserved.ID, "RESERVATION", "BRIGADE_RESERVATION_FAILED", err.Error(), reserved.Version)
		releaseErr := s.release(ctx, brigadeID, actor)
		return nil, errors.Join(fmt.Errorf("reserve brigade: %w", err), transitionErr, releaseErr)
	}

	return reserved, nil
}

// getNewTicket получает заявку через Ticket Service и требует статус NEW.
// Отсутствие заявки даёт ErrNotFound, другой статус — ErrConflict.
func (s *Service) getNewTicket(ctx context.Context, id uuid.UUID) (*ticketv1.Ticket, error) {
	response, err := s.deps.Tickets.GetTicket(ctx, &ticketv1.GetTicketRequest{TicketId: id.String()})

	if err != nil {

		if status.Code(err) == codes.NotFound {
			return nil, models.ErrNotFound
		}

		return nil, fmt.Errorf("get ticket: %w", err)
	}

	if response.GetTicket() == nil {
		return nil, models.ErrNotFound
	}

	if response.GetTicket().GetStatus() != ticketv1.TicketStatus_TICKET_STATUS_NEW {
		return nil, fmt.Errorf("%w: ticket is not NEW", models.ErrConflict)
	}

	return response.GetTicket(), nil
}

// failAndRelease фиксирует FAILED с причиной cause и освобождает бригаду после
// успешной смены статуса. Возвращает nil и исходную причину, присоединяя ошибки
// перехода или освобождения; cause должен быть ненулевым.
func (s *Service) failAndRelease(ctx context.Context, op *models.Operation, actor uuid.UUID, cause error) (*models.Operation, error) {
	failed, transitionErr := s.repo.SetFailed(ctx, op.ID, dispatchFailureStage(op), dispatchFailureCode(cause), cause.Error(), op.Version)

	if transitionErr != nil {
		return nil, errors.Join(cause, transitionErr)
	}

	if failed.BrigadeID != nil {

		if releaseErr := s.release(ctx, *failed.BrigadeID, actor); releaseErr != nil {
			return nil, errors.Join(cause, releaseErr)
		}

	}

	return nil, cause
}

// dispatchFailureCode сопоставляет отсутствие зависимости, конфликт или gRPC Unavailable
// с кодом сбоя диспетчеризации; прочие ошибки получают DISPATCH_FAILED.
func dispatchFailureCode(err error) string {
	switch {
	case errors.Is(err, models.ErrNotFound):
		return "DEPENDENCY_NOT_FOUND"
	case errors.Is(err, models.ErrConflict):
		return "STATE_CONFLICT"
	case status.Code(err) == codes.Unavailable:
		return "DEPENDENCY_UNAVAILABLE"
	default:
		return "DISPATCH_FAILED"
	}
}

// dispatchFailureStage определяет этап сбоя: ROUTING для RESERVED,
// TICKET_ASSIGNMENT для CONFIRMING и DISPATCH для остальных статусов.
func dispatchFailureStage(operation *models.Operation) string {
	switch operation.Status {
	case models.StatusReserved:
		return "ROUTING"
	case models.StatusConfirming:
		return "TICKET_ASSIGNMENT"
	default:
		return "DISPATCH"
	}
}

// operationInput собирает входные данные операции из снимка заявки и параметров.
// Некорректные UUID ведомства или категории, пустой либо UNSPECIFIED приоритет
// возвращает как ErrInvalidArgument.
func operationInput(ticket *ticketv1.Ticket, ticketID, requestedBy uuid.UUID, mode models.Mode, ttl time.Duration) (models.CreateOperationInput, error) {
	departmentID, err := uuid.Parse(ticket.GetDepartmentId())

	if err != nil {
		return models.CreateOperationInput{}, fmt.Errorf("%w: ticket department_id", models.ErrInvalidArgument)
	}

	categoryID, err := uuid.Parse(ticket.GetCategoryId())

	if err != nil {
		return models.CreateOperationInput{}, fmt.Errorf("%w: ticket category_id", models.ErrInvalidArgument)
	}

	priority := strings.TrimPrefix(ticket.GetPriority().String(), "TICKET_PRIORITY_")

	if priority == "" || priority == "UNSPECIFIED" {
		return models.CreateOperationInput{}, fmt.Errorf("%w: ticket priority", models.ErrInvalidArgument)
	}

	return models.CreateOperationInput{
		TicketID:     ticketID,
		DepartmentID: departmentID,
		CategoryID:   categoryID,
		Priority:     priority,
		RequestedBy:  requestedBy,
		Mode:         mode,
		TTL:          ttl,
	}, nil
}

// release переводит бригаду в AVAILABLE от имени actor с причиной снятия резерва.
// Ошибку Brigade Service записывает в журнал и возвращает вызывающему коду.
func (s *Service) release(ctx context.Context, id, actor uuid.UUID) error {
	_, err := s.deps.Brigades.SetBrigadeStatus(ctx, &brigadev1.SetBrigadeStatusRequest{
		BrigadeId:       id.String(),
		Status:          brigadev1.BrigadeStatus_BRIGADE_STATUS_AVAILABLE,
		Reason:          "dispatch reservation released",
		ChangedByUserId: actor.String(),
	})

	if err != nil {
		s.log.Error("release brigade", zap.Error(err), zap.String("brigade_id", id.String()))
	}

	return err
}

// compensationContext заменяет исходящие метаданные данными инициатора операции,
// ролью dispatcher и, при наличии, ведомством для восстановления фоновых операций.
func compensationContext(ctx context.Context, operation *models.Operation) context.Context {
	values := []string{
		"x-actor-user-id", operation.RequestedBy.String(),
		"x-actor-roles", "dispatcher",
	}

	if operation.DepartmentID != nil {
		values = append(values, "x-actor-department-id", operation.DepartmentID.String())
	}

	return metadata.NewOutgoingContext(ctx, metadata.Pairs(values...))
}

// cancelRoute пытается перевести маршрут в CANCELLED; ошибку записывает в журнал.
func (s *Service) cancelRoute(ctx context.Context, id string) {
	_, err := s.deps.Routing.SetRouteStatus(ctx, &routingv1.SetRouteStatusRequest{
		Id:     id,
		Status: routingv1.RouteStatus_ROUTE_STATUS_CANCELLED,
	})

	if err != nil {
		s.log.Error("cancel route", zap.Error(err), zap.String("route_id", id))
	}

}

// forwardMetadata сохраняет непустые исходящие метаданные, иначе копирует входящие
// в исходящие для вызовов зависимостей. При отсутствии метаданных возвращает ctx.
func forwardMetadata(ctx context.Context) context.Context {

	if outgoing, ok := metadata.FromOutgoingContext(ctx); ok && len(outgoing) > 0 {
		return ctx
	}

	if incoming, ok := metadata.FromIncomingContext(ctx); ok {
		return metadata.NewOutgoingContext(ctx, incoming.Copy())
	}

	return ctx
}

// uuidStrings создаёт срез строковых UUID в исходном порядке; пустой вход даёт пустой срез.
func uuidStrings(values []uuid.UUID) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}
