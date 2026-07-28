package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"brigade/models"
	"brigade/src/core/service"

	brigadev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/brigade/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type mockService struct {
	brigadeFunc     func(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error)
	getFunc         func(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error)
	listFunc        func(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error)
	statusFunc      func(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error)
	addMemberFunc   func(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error)
	createSkillFunc func(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error)
	scheduleFunc    func(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error)
	zoneFunc        func(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error)
	coversFunc      func(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error)
}

func (m *mockService) CreateBrigade(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error) {
	return m.brigadeFunc(ctx, in)
}
func (m *mockService) GetBrigadeByID(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
	return m.getFunc(ctx, in)
}
func (m *mockService) ListBrigades(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error) {
	return m.listFunc(ctx, in)
}
func (m *mockService) UpdateBrigade(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error) {
	return nil, nil
}
func (m *mockService) DeactivateBrigade(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error) {
	return nil, nil
}
func (m *mockService) ArchiveBrigade(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error) {
	return nil, nil
}
func (m *mockService) SetBrigadeStatus(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error) {
	return m.statusFunc(ctx, in)
}
func (m *mockService) GetBrigadeStatusHistory(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error) {
	return nil, nil
}
func (m *mockService) GetAvailableBrigades(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error) {
	return nil, nil
}
func (m *mockService) CheckBrigadeCanHandleTicket(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error) {
	return nil, nil
}
func (m *mockService) AddBrigadeMember(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error) {
	return m.addMemberFunc(ctx, in)
}
func (m *mockService) RemoveBrigadeMember(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error) {
	return nil, nil
}
func (m *mockService) ChangeBrigadeMemberRole(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error) {
	return nil, nil
}
func (m *mockService) SetBrigadeMemberAvailability(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error) {
	return nil, nil
}
func (m *mockService) ListBrigadeMembers(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error) {
	return nil, nil
}
func (m *mockService) GetBrigadeMemberHistory(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error) {
	return nil, nil
}
func (m *mockService) GetBrigadeMemberStatusHistory(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error) {
	return nil, nil
}
func (m *mockService) GetBrigadeByUserID(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error) {
	return nil, nil
}
func (m *mockService) CreateSkill(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error) {
	return m.createSkillFunc(ctx, in)
}
func (m *mockService) UpdateSkill(ctx context.Context, in *models.UpdateSkillInput) (*models.UpdateSkillResult, error) {
	return nil, nil
}
func (m *mockService) DeactivateSkill(ctx context.Context, in *models.DeactivateSkillInput) (*models.DeactivateSkillResult, error) {
	return nil, nil
}
func (m *mockService) ListSkills(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error) {
	return nil, nil
}
func (m *mockService) AddBrigadeSkill(ctx context.Context, in *models.AddBrigadeSkillInput) (*models.AddBrigadeSkillResult, error) {
	return nil, nil
}
func (m *mockService) RemoveBrigadeSkill(ctx context.Context, in *models.RemoveBrigadeSkillInput) (*models.RemoveBrigadeSkillResult, error) {
	return nil, nil
}
func (m *mockService) ListBrigadeSkills(ctx context.Context, in *models.ListBrigadeSkillsInput) (*models.ListBrigadeSkillsResult, error) {
	return nil, nil
}
func (m *mockService) SetBrigadeSchedule(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error) {
	return m.scheduleFunc(ctx, in)
}
func (m *mockService) ListBrigadeSchedule(ctx context.Context, in *models.ListBrigadeScheduleInput) (*models.ListBrigadeScheduleResult, error) {
	return nil, nil
}
func (m *mockService) CreateBrigadeZone(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error) {
	return m.zoneFunc(ctx, in)
}
func (m *mockService) UpdateBrigadeZone(ctx context.Context, in *models.UpdateBrigadeZoneInput) (*models.UpdateBrigadeZoneResult, error) {
	return nil, nil
}
func (m *mockService) DeleteBrigadeZone(ctx context.Context, in *models.DeleteBrigadeZoneInput) (*models.DeleteBrigadeZoneResult, error) {
	return nil, nil
}
func (m *mockService) ListBrigadeZones(ctx context.Context, in *models.ListBrigadeZonesInput) (*models.ListBrigadeZonesResult, error) {
	return nil, nil
}
func (m *mockService) CheckBrigadeCoversPoint(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error) {
	return m.coversFunc(ctx, in)
}
func (m *mockService) FindBrigadesByPoint(ctx context.Context, in *models.FindBrigadesByPointInput) (*models.FindBrigadesByPointResult, error) {
	return nil, nil
}

func newTestBrigadeHandler(mock *mockService) *BrigadeHandler {
	return NewBrigadeHandler(&service.Service{
		BrigadeService:  mock,
		MemberService:   mock,
		SkillService:    mock,
		ScheduleService: mock,
		ZoneService:     mock,
	}, zap.NewNop())
}

func brigadeHandlerContext(userID uuid.UUID, departmentID uuid.UUID, roles string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-actor-user-id", userID.String(),
		"x-actor-department-id", departmentID.String(),
		"x-actor-roles", roles,
		"x-request-id", "request-1",
		"x-trace-id", "trace-1",
	))
}

func assertBrigadeGRPCCode(t *testing.T, err error, expected codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %v", err)
	}
	if st.Code() != expected {
		t.Fatalf("expected grpc code %v, got %v", expected, st.Code())
	}
}

func TestBrigadeHandler_CreateBrigade_Success(t *testing.T) {
	departmentID := uuid.New()
	userID := uuid.New()
	brigadeID := uuid.New()
	mock := &mockService{
		brigadeFunc: func(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error) {
			if in.DepartmentID != departmentID {
				t.Fatalf("expected department id %s, got %s", departmentID, in.DepartmentID)
			}
			if in.ActorUserID == nil || *in.ActorUserID != userID {
				t.Fatalf("expected actor user %s, got %v", userID, in.ActorUserID)
			}
			if in.ActorDepartmentID == nil || *in.ActorDepartmentID != departmentID {
				t.Fatalf("expected actor department %s, got %v", departmentID, in.ActorDepartmentID)
			}
			if len(in.ActorRoles) != 2 {
				t.Fatalf("expected 2 roles, got %#v", in.ActorRoles)
			}
			return &models.CreateBrigadeResult{Brigade: testHandlerBrigade(brigadeID, departmentID)}, nil
		},
	}
	h := newTestBrigadeHandler(mock)

	resp, err := h.CreateBrigade(brigadeHandlerContext(userID, departmentID, "admin, dispatcher"), &brigadev1.CreateBrigadeRequest{
		DepartmentId: departmentID.String(),
		Name:         "North crew",
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.GetBrigade().GetId() != brigadeID.String() {
		t.Fatalf("expected brigade id %s, got %s", brigadeID, resp.GetBrigade().GetId())
	}
}

func TestBrigadeHandler_CreateBrigade_InvalidDepartmentID(t *testing.T) {
	h := newTestBrigadeHandler(&mockService{})

	resp, err := h.CreateBrigade(context.Background(), &brigadev1.CreateBrigadeRequest{DepartmentId: "bad-id"})

	if resp != nil {
		t.Fatal("expected nil response")
	}
	assertBrigadeGRPCCode(t, err, codes.InvalidArgument)
}

func TestBrigadeHandler_GetBrigadeByID_NotFound(t *testing.T) {
	brigadeID := uuid.New()
	mock := &mockService{
		getFunc: func(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
			return nil, models.ErrNotFound
		},
	}
	h := newTestBrigadeHandler(mock)

	resp, err := h.GetBrigadeByID(context.Background(), &brigadev1.GetBrigadeByIDRequest{Id: brigadeID.String()})

	if resp != nil {
		t.Fatal("expected nil response")
	}
	assertBrigadeGRPCCode(t, err, codes.NotFound)
}

func TestBrigadeHandler_ListBrigades_Success(t *testing.T) {
	departmentID := uuid.New()
	statusValue := brigadev1.BrigadeStatus_BRIGADE_STATUS_ACTIVE
	mock := &mockService{
		listFunc: func(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error) {
			if in.DepartmentID == nil || *in.DepartmentID != departmentID {
				t.Fatalf("expected department id %s, got %v", departmentID, in.DepartmentID)
			}
			if in.Status == nil || *in.Status != models.BrigadeStatusActive {
				t.Fatalf("expected active status, got %v", in.Status)
			}
			return &models.ListBrigadesResult{Brigades: []*models.Brigade{testHandlerBrigade(uuid.New(), departmentID)}, Total: 1}, nil
		},
	}
	h := newTestBrigadeHandler(mock)
	departmentRaw := departmentID.String()

	resp, err := h.ListBrigades(context.Background(), &brigadev1.ListBrigadesRequest{
		DepartmentId: &departmentRaw,
		Status:       &statusValue,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.GetTotal() != 1 {
		t.Fatalf("expected total 1, got %d", resp.GetTotal())
	}
}

func TestBrigadeHandler_AddMember_Success(t *testing.T) {
	departmentID := uuid.New()
	userID := uuid.New()
	brigadeID := uuid.New()
	memberUserID := uuid.New()
	memberID := uuid.New()
	mock := &mockService{
		addMemberFunc: func(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error) {
			if in.BrigadeID != brigadeID || in.UserID != memberUserID {
				t.Fatalf("unexpected ids: %#v", in)
			}
			if in.Role != models.BrigadeMemberRoleLead {
				t.Fatalf("expected lead role, got %s", in.Role)
			}
			return &models.AddBrigadeMemberResult{Member: testHandlerMember(memberID, brigadeID, memberUserID)}, nil
		},
	}
	h := newTestBrigadeHandler(mock)

	resp, err := h.AddBrigadeMember(brigadeHandlerContext(userID, departmentID, "admin"), &brigadev1.AddBrigadeMemberRequest{
		BrigadeId: brigadeID.String(),
		UserId:    memberUserID.String(),
		Role:      brigadev1.BrigadeMemberRole_BRIGADE_MEMBER_ROLE_LEAD,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.GetMember().GetId() != memberID.String() {
		t.Fatalf("expected member id %s, got %s", memberID, resp.GetMember().GetId())
	}
}

func TestBrigadeHandler_CreateSkill_MapsPermissionDenied(t *testing.T) {
	mock := &mockService{
		createSkillFunc: func(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error) {
			return nil, models.ErrPermissionDenied
		},
	}
	h := newTestBrigadeHandler(mock)

	resp, err := h.CreateSkill(context.Background(), &brigadev1.CreateSkillRequest{Code: "plumbing", Name: "Plumbing"})

	if resp != nil {
		t.Fatal("expected nil response")
	}
	assertBrigadeGRPCCode(t, err, codes.PermissionDenied)
}

func TestBrigadeHandler_SetSchedule_ParsesItems(t *testing.T) {
	brigadeID := uuid.New()
	mock := &mockService{
		scheduleFunc: func(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error) {
			if len(in.Items) != 1 {
				t.Fatalf("expected one item, got %d", len(in.Items))
			}
			if in.Items[0].ValidFrom == nil || in.Items[0].ValidTo == nil {
				t.Fatal("expected valid date range")
			}
			return &models.SetBrigadeScheduleResult{Schedule: []*models.BrigadeSchedule{{
				ID:        uuid.New(),
				BrigadeID: brigadeID,
				DayOfWeek: 1,
				StartsAt:  "09:00:00",
				EndsAt:    "18:00:00",
				Timezone:  "UTC",
				Active:    true,
			}}}, nil
		},
	}
	h := newTestBrigadeHandler(mock)
	from := "2026-01-01"
	to := "2026-12-31"

	resp, err := h.SetBrigadeSchedule(context.Background(), &brigadev1.SetBrigadeScheduleRequest{
		BrigadeId: brigadeID.String(),
		Items: []*brigadev1.BrigadeScheduleItem{{
			DayOfWeek: 1,
			StartsAt:  "09:00",
			EndsAt:    "18:00",
			Timezone:  "UTC",
			ValidFrom: &from,
			ValidTo:   &to,
		}},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(resp.GetSchedule()) != 1 {
		t.Fatalf("expected one schedule item, got %d", len(resp.GetSchedule()))
	}
}

func TestBrigadeHandler_CreateZone_Success(t *testing.T) {
	departmentID := uuid.New()
	brigadeID := uuid.New()
	zoneID := uuid.New()
	mock := &mockService{
		zoneFunc: func(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error) {
			if in.GeoJSON == "" {
				t.Fatal("expected geojson")
			}
			return &models.CreateBrigadeZoneResult{Zone: &models.BrigadeZone{
				ID:           zoneID,
				BrigadeID:    brigadeID,
				DepartmentID: departmentID,
				Name:         in.Name,
				GeoJSON:      in.GeoJSON,
				Priority:     in.Priority,
				Active:       true,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}}, nil
		},
	}
	h := newTestBrigadeHandler(mock)

	resp, err := h.CreateBrigadeZone(context.Background(), &brigadev1.CreateBrigadeZoneRequest{
		BrigadeId:    brigadeID.String(),
		DepartmentId: departmentID.String(),
		Name:         "North",
		GeoJson:      "{}",
		Priority:     1,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.GetZone().GetId() != zoneID.String() {
		t.Fatalf("expected zone id %s, got %s", zoneID, resp.GetZone().GetId())
	}
}

func TestBrigadeHandler_CheckCovers_Success(t *testing.T) {
	brigadeID := uuid.New()
	mock := &mockService{
		coversFunc: func(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error) {
			if in.Longitude != 37.62 || in.Latitude != 55.75 {
				t.Fatalf("unexpected point: %f %f", in.Longitude, in.Latitude)
			}
			return &models.CheckBrigadeCoversPointResult{Covers: true}, nil
		},
	}
	h := newTestBrigadeHandler(mock)

	resp, err := h.CheckBrigadeCoversPoint(context.Background(), &brigadev1.CheckBrigadeCoversPointRequest{
		BrigadeId: brigadeID.String(),
		Longitude: 37.62,
		Latitude:  55.75,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !resp.GetCovers() {
		t.Fatal("expected covers true")
	}
}

func TestBrigadeErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{name: "validation", err: models.ErrValidation, code: codes.InvalidArgument},
		{name: "invalid status", err: models.ErrInvalidStatus, code: codes.InvalidArgument},
		{name: "not found", err: models.ErrNotFound, code: codes.NotFound},
		{name: "already exists", err: models.ErrAlreadyExists, code: codes.AlreadyExists},
		{name: "permission", err: models.ErrPermissionDenied, code: codes.PermissionDenied},
		{name: "unavailable", err: models.ErrBrigadeUnavailable, code: codes.FailedPrecondition},
		{name: "department inactive", err: models.ErrDepartmentInactive, code: codes.FailedPrecondition},
		{name: "dependency unavailable", err: models.ErrDependencyUnavailable, code: codes.Unavailable},
		{name: "unknown", err: errors.New("boom"), code: codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := brigadeErrorCode(tt.err); got != tt.code {
				t.Fatalf("expected %v, got %v", tt.code, got)
			}
		})
	}
}

func testHandlerBrigade(id uuid.UUID, departmentID uuid.UUID) *models.Brigade {
	return &models.Brigade{
		ID:           id,
		DepartmentID: departmentID,
		Name:         "North crew",
		Status:       models.BrigadeStatusActive,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func testHandlerMember(id uuid.UUID, brigadeID uuid.UUID, userID uuid.UUID) *models.BrigadeMember {
	return &models.BrigadeMember{
		ID:                 id,
		BrigadeID:          brigadeID,
		UserID:             userID,
		Role:               models.BrigadeMemberRoleLead,
		Active:             true,
		AvailabilityStatus: models.BrigadeMemberAvailabilityAvailable,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
}
