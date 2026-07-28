package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"brigade/models"
	"brigade/src/core/repository"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockBrigadeRepo struct {
	createBrigadeFunc                 func(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error)
	getBrigadeByIDFunc                func(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error)
	listBrigadesFunc                  func(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error)
	updateBrigadeFunc                 func(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error)
	deactivateBrigadeFunc             func(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error)
	archiveBrigadeFunc                func(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error)
	setBrigadeStatusFunc              func(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error)
	getBrigadeStatusHistoryFunc       func(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error)
	checkBrigadeReadinessFunc         func(ctx context.Context, brigadeID uuid.UUID, requireOnShift bool, requiredRoles []models.BrigadeMemberRole) ([]string, error)
	getAvailableBrigadesFunc          func(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error)
	checkBrigadeCanHandleTicketFunc   func(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error)
	addBrigadeMemberFunc              func(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error)
	removeBrigadeMemberFunc           func(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error)
	changeBrigadeMemberRoleFunc       func(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error)
	setBrigadeMemberAvailabilityFunc  func(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error)
	listBrigadeMembersFunc            func(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error)
	getBrigadeMemberHistoryFunc       func(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error)
	getBrigadeMemberStatusHistoryFunc func(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error)
	getBrigadeByUserIDFunc            func(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error)
	createSkillFunc                   func(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error)
	updateSkillFunc                   func(ctx context.Context, in *models.UpdateSkillInput) (*models.UpdateSkillResult, error)
	deactivateSkillFunc               func(ctx context.Context, in *models.DeactivateSkillInput) (*models.DeactivateSkillResult, error)
	listSkillsFunc                    func(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error)
	addBrigadeSkillFunc               func(ctx context.Context, in *models.AddBrigadeSkillInput) (*models.AddBrigadeSkillResult, error)
	removeBrigadeSkillFunc            func(ctx context.Context, in *models.RemoveBrigadeSkillInput) (*models.RemoveBrigadeSkillResult, error)
	listBrigadeSkillsFunc             func(ctx context.Context, in *models.ListBrigadeSkillsInput) (*models.ListBrigadeSkillsResult, error)
	setBrigadeScheduleFunc            func(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error)
	listBrigadeScheduleFunc           func(ctx context.Context, in *models.ListBrigadeScheduleInput) (*models.ListBrigadeScheduleResult, error)
	getBrigadeZoneByIDFunc            func(ctx context.Context, zoneID uuid.UUID) (*models.BrigadeZone, error)
	createBrigadeZoneFunc             func(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error)
	updateBrigadeZoneFunc             func(ctx context.Context, in *models.UpdateBrigadeZoneInput) (*models.UpdateBrigadeZoneResult, error)
	deleteBrigadeZoneFunc             func(ctx context.Context, in *models.DeleteBrigadeZoneInput) (*models.DeleteBrigadeZoneResult, error)
	listBrigadeZonesFunc              func(ctx context.Context, in *models.ListBrigadeZonesInput) (*models.ListBrigadeZonesResult, error)
	checkBrigadeCoversPointFunc       func(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error)
	findBrigadesByPointFunc           func(ctx context.Context, in *models.FindBrigadesByPointInput) (*models.FindBrigadesByPointResult, error)
}

func (m *mockBrigadeRepo) CreateBrigade(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error) {
	return m.createBrigadeFunc(ctx, in)
}
func (m *mockBrigadeRepo) GetBrigadeByID(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
	return m.getBrigadeByIDFunc(ctx, in)
}
func (m *mockBrigadeRepo) ListBrigades(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error) {
	return m.listBrigadesFunc(ctx, in)
}
func (m *mockBrigadeRepo) UpdateBrigade(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error) {
	return m.updateBrigadeFunc(ctx, in)
}
func (m *mockBrigadeRepo) DeactivateBrigade(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error) {
	return m.deactivateBrigadeFunc(ctx, in)
}
func (m *mockBrigadeRepo) ArchiveBrigade(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error) {
	return m.archiveBrigadeFunc(ctx, in)
}
func (m *mockBrigadeRepo) SetBrigadeStatus(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error) {
	return m.setBrigadeStatusFunc(ctx, in)
}
func (m *mockBrigadeRepo) GetBrigadeStatusHistory(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error) {
	return m.getBrigadeStatusHistoryFunc(ctx, in)
}
func (m *mockBrigadeRepo) CheckBrigadeReadiness(ctx context.Context, brigadeID uuid.UUID, requireOnShift bool, requiredRoles []models.BrigadeMemberRole) ([]string, error) {
	return m.checkBrigadeReadinessFunc(ctx, brigadeID, requireOnShift, requiredRoles)
}
func (m *mockBrigadeRepo) GetAvailableBrigades(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error) {
	return m.getAvailableBrigadesFunc(ctx, in)
}
func (m *mockBrigadeRepo) CheckBrigadeCanHandleTicket(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error) {
	return m.checkBrigadeCanHandleTicketFunc(ctx, in)
}
func (m *mockBrigadeRepo) AddBrigadeMember(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error) {
	return m.addBrigadeMemberFunc(ctx, in)
}
func (m *mockBrigadeRepo) RemoveBrigadeMember(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error) {
	return m.removeBrigadeMemberFunc(ctx, in)
}
func (m *mockBrigadeRepo) ChangeBrigadeMemberRole(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error) {
	return m.changeBrigadeMemberRoleFunc(ctx, in)
}
func (m *mockBrigadeRepo) SetBrigadeMemberAvailability(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error) {
	return m.setBrigadeMemberAvailabilityFunc(ctx, in)
}
func (m *mockBrigadeRepo) ListBrigadeMembers(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error) {
	return m.listBrigadeMembersFunc(ctx, in)
}
func (m *mockBrigadeRepo) GetBrigadeMemberHistory(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error) {
	return m.getBrigadeMemberHistoryFunc(ctx, in)
}
func (m *mockBrigadeRepo) GetBrigadeMemberStatusHistory(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error) {
	return m.getBrigadeMemberStatusHistoryFunc(ctx, in)
}
func (m *mockBrigadeRepo) GetBrigadeByUserID(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error) {
	return m.getBrigadeByUserIDFunc(ctx, in)
}
func (m *mockBrigadeRepo) CreateSkill(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error) {
	return m.createSkillFunc(ctx, in)
}
func (m *mockBrigadeRepo) UpdateSkill(ctx context.Context, in *models.UpdateSkillInput) (*models.UpdateSkillResult, error) {
	return m.updateSkillFunc(ctx, in)
}
func (m *mockBrigadeRepo) DeactivateSkill(ctx context.Context, in *models.DeactivateSkillInput) (*models.DeactivateSkillResult, error) {
	return m.deactivateSkillFunc(ctx, in)
}
func (m *mockBrigadeRepo) ListSkills(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error) {
	return m.listSkillsFunc(ctx, in)
}
func (m *mockBrigadeRepo) AddBrigadeSkill(ctx context.Context, in *models.AddBrigadeSkillInput) (*models.AddBrigadeSkillResult, error) {
	return m.addBrigadeSkillFunc(ctx, in)
}
func (m *mockBrigadeRepo) RemoveBrigadeSkill(ctx context.Context, in *models.RemoveBrigadeSkillInput) (*models.RemoveBrigadeSkillResult, error) {
	return m.removeBrigadeSkillFunc(ctx, in)
}
func (m *mockBrigadeRepo) ListBrigadeSkills(ctx context.Context, in *models.ListBrigadeSkillsInput) (*models.ListBrigadeSkillsResult, error) {
	return m.listBrigadeSkillsFunc(ctx, in)
}
func (m *mockBrigadeRepo) SetBrigadeSchedule(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error) {
	return m.setBrigadeScheduleFunc(ctx, in)
}
func (m *mockBrigadeRepo) ListBrigadeSchedule(ctx context.Context, in *models.ListBrigadeScheduleInput) (*models.ListBrigadeScheduleResult, error) {
	return m.listBrigadeScheduleFunc(ctx, in)
}
func (m *mockBrigadeRepo) GetBrigadeZoneByID(ctx context.Context, zoneID uuid.UUID) (*models.BrigadeZone, error) {
	return m.getBrigadeZoneByIDFunc(ctx, zoneID)
}
func (m *mockBrigadeRepo) CreateBrigadeZone(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error) {
	return m.createBrigadeZoneFunc(ctx, in)
}
func (m *mockBrigadeRepo) UpdateBrigadeZone(ctx context.Context, in *models.UpdateBrigadeZoneInput) (*models.UpdateBrigadeZoneResult, error) {
	return m.updateBrigadeZoneFunc(ctx, in)
}
func (m *mockBrigadeRepo) DeleteBrigadeZone(ctx context.Context, in *models.DeleteBrigadeZoneInput) (*models.DeleteBrigadeZoneResult, error) {
	return m.deleteBrigadeZoneFunc(ctx, in)
}
func (m *mockBrigadeRepo) ListBrigadeZones(ctx context.Context, in *models.ListBrigadeZonesInput) (*models.ListBrigadeZonesResult, error) {
	return m.listBrigadeZonesFunc(ctx, in)
}
func (m *mockBrigadeRepo) CheckBrigadeCoversPoint(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error) {
	return m.checkBrigadeCoversPointFunc(ctx, in)
}
func (m *mockBrigadeRepo) FindBrigadesByPoint(ctx context.Context, in *models.FindBrigadesByPointInput) (*models.FindBrigadesByPointResult, error) {
	return m.findBrigadesByPointFunc(ctx, in)
}

type mockDepartmentClient struct {
	getDepartmentByIDFunc func(ctx context.Context, in *departmentv1.GetDepartmentByIDRequest, opts ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error)
}

func (m *mockDepartmentClient) CreateDepartment(ctx context.Context, in *departmentv1.CreateDepartmentRequest, opts ...grpc.CallOption) (*departmentv1.CreateDepartmentResponse, error) {
	return nil, nil
}
func (m *mockDepartmentClient) GetDepartmentByID(ctx context.Context, in *departmentv1.GetDepartmentByIDRequest, opts ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error) {
	return m.getDepartmentByIDFunc(ctx, in, opts...)
}
func (m *mockDepartmentClient) ListDepartments(ctx context.Context, in *departmentv1.ListDepartmentsRequest, opts ...grpc.CallOption) (*departmentv1.ListDepartmentsResponse, error) {
	return nil, nil
}
func (m *mockDepartmentClient) UpdateDepartment(ctx context.Context, in *departmentv1.UpdateDepartmentRequest, opts ...grpc.CallOption) (*departmentv1.UpdateDepartmentResponse, error) {
	return nil, nil
}
func (m *mockDepartmentClient) DeleteDepartment(ctx context.Context, in *departmentv1.DeleteDepartmentRequest, opts ...grpc.CallOption) (*departmentv1.DeleteDepartmentResponse, error) {
	return nil, nil
}

func newTestRepo(mock *mockBrigadeRepo) *repository.Repo {
	return &repository.Repo{
		BrigadeRepo:  mock,
		MemberRepo:   mock,
		SkillRepo:    mock,
		ScheduleRepo: mock,
		ZoneRepo:     mock,
	}
}

func activeDepartmentClient(t *testing.T, departmentID uuid.UUID) *mockDepartmentClient {
	t.Helper()
	return &mockDepartmentClient{
		getDepartmentByIDFunc: func(ctx context.Context, in *departmentv1.GetDepartmentByIDRequest, opts ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error) {
			if in.Id != departmentID.String() {
				t.Fatalf("expected department id %s, got %s", departmentID, in.Id)
			}
			return &departmentv1.GetDepartmentByIDResponse{
				Department: &departmentv1.Department{
					Id:     departmentID.String(),
					Name:   "Roads",
					Status: departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE,
				},
			}, nil
		},
	}
}

func testBrigade(id uuid.UUID, departmentID uuid.UUID, status models.BrigadeStatus) *models.Brigade {
	return &models.Brigade{
		ID:           id,
		DepartmentID: departmentID,
		Name:         "North crew",
		Status:       status,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func testMember(id uuid.UUID, brigadeID uuid.UUID, userID uuid.UUID) *models.BrigadeMember {
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

func TestBrigadeService_CreateBrigade_Success(t *testing.T) {
	departmentID := uuid.New()
	brigadeID := uuid.New()
	mock := &mockBrigadeRepo{
		createBrigadeFunc: func(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error) {
			if in.DepartmentID != departmentID {
				t.Fatalf("expected department id %s, got %s", departmentID, in.DepartmentID)
			}
			return &models.CreateBrigadeResult{Brigade: testBrigade(brigadeID, departmentID, models.BrigadeStatusInactive)}, nil
		},
	}
	svc := NewBrigadeService(newTestRepo(mock), activeDepartmentClient(t, departmentID), zap.NewNop())

	result, err := svc.CreateBrigade(context.Background(), &models.CreateBrigadeInput{
		DepartmentID:      departmentID,
		Name:              "North crew",
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Brigade.ID != brigadeID {
		t.Fatalf("expected brigade id %s, got %s", brigadeID, result.Brigade.ID)
	}
}

func TestBrigadeService_CreateBrigade_DepartmentInactive(t *testing.T) {
	departmentID := uuid.New()
	mock := &mockBrigadeRepo{
		createBrigadeFunc: func(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error) {
			t.Fatal("repo should not be called")
			return nil, nil
		},
	}
	client := &mockDepartmentClient{
		getDepartmentByIDFunc: func(ctx context.Context, in *departmentv1.GetDepartmentByIDRequest, opts ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error) {
			return &departmentv1.GetDepartmentByIDResponse{
				Department: &departmentv1.Department{Id: departmentID.String(), Status: departmentv1.DepartmentStatus_DEPARTMENT_STATUS_INACTIVE},
			}, nil
		},
	}
	svc := NewBrigadeService(newTestRepo(mock), client, zap.NewNop())

	result, err := svc.CreateBrigade(context.Background(), &models.CreateBrigadeInput{
		DepartmentID: departmentID,
		Name:         "North crew",
		ActorRoles:   []string{"admin"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, models.ErrDepartmentInactive) {
		t.Fatalf("expected ErrDepartmentInactive, got %v", err)
	}
}

func TestMapDepartmentServiceError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
	}{
		{name: "not found", err: status.Error(codes.NotFound, "missing"), target: models.ErrNotFound},
		{name: "unavailable", err: status.Error(codes.Unavailable, "down"), target: models.ErrDependencyUnavailable},
		{name: "deadline", err: status.Error(codes.DeadlineExceeded, "slow"), target: models.ErrDependencyUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapDepartmentServiceError(tt.err)
			if !errors.Is(got, tt.target) {
				t.Fatalf("expected %v, got %v", tt.target, got)
			}
		})
	}
}

func TestBrigadeService_CreateBrigade_DepartmentRetry(t *testing.T) {
	departmentID := uuid.New()
	brigadeID := uuid.New()
	attempts := 0
	client := &mockDepartmentClient{
		getDepartmentByIDFunc: func(ctx context.Context, in *departmentv1.GetDepartmentByIDRequest, opts ...grpc.CallOption) (*departmentv1.GetDepartmentByIDResponse, error) {
			attempts++
			if attempts == 1 {
				return nil, status.Error(codes.Unavailable, "temporary")
			}
			return &departmentv1.GetDepartmentByIDResponse{
				Department: &departmentv1.Department{Id: departmentID.String(), Status: departmentv1.DepartmentStatus_DEPARTMENT_STATUS_ACTIVE},
			}, nil
		},
	}
	mock := &mockBrigadeRepo{
		createBrigadeFunc: func(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error) {
			return &models.CreateBrigadeResult{Brigade: testBrigade(brigadeID, departmentID, models.BrigadeStatusInactive)}, nil
		},
	}
	svc := NewBrigadeService(newTestRepo(mock), client, zap.NewNop())

	_, err := svc.CreateBrigade(context.Background(), &models.CreateBrigadeInput{
		DepartmentID: departmentID,
		Name:         "North crew",
		ActorRoles:   []string{"admin"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestBrigadeService_GetBrigadeByID_DispatcherWrongDepartment(t *testing.T) {
	departmentID := uuid.New()
	otherDepartmentID := uuid.New()
	brigadeID := uuid.New()
	mock := &mockBrigadeRepo{
		getBrigadeByIDFunc: func(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
			return &models.GetBrigadeByIDResult{Brigade: testBrigade(brigadeID, otherDepartmentID, models.BrigadeStatusActive)}, nil
		},
	}
	svc := NewBrigadeService(newTestRepo(mock), nil, zap.NewNop())

	result, err := svc.GetBrigadeByID(context.Background(), &models.GetBrigadeByIDInput{
		ID:                brigadeID,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied, got %v", err)
	}
}

func TestBrigadeService_ListBrigades_DispatcherScopedToDepartment(t *testing.T) {
	departmentID := uuid.New()
	mock := &mockBrigadeRepo{
		listBrigadesFunc: func(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error) {
			if in.DepartmentID == nil || *in.DepartmentID != departmentID {
				t.Fatalf("expected department scope %s, got %v", departmentID, in.DepartmentID)
			}
			return &models.ListBrigadesResult{Brigades: []*models.Brigade{testBrigade(uuid.New(), departmentID, models.BrigadeStatusActive)}, Total: 1}, nil
		},
	}
	svc := NewBrigadeService(newTestRepo(mock), nil, zap.NewNop())

	result, err := svc.ListBrigades(context.Background(), &models.ListBrigadesInput{
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected total 1, got %d", result.Total)
	}
}

func TestBrigadeService_SetBrigadeStatus_ReadinessFailure(t *testing.T) {
	departmentID := uuid.New()
	brigadeID := uuid.New()
	mock := &mockBrigadeRepo{
		getBrigadeByIDFunc: func(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
			return &models.GetBrigadeByIDResult{Brigade: testBrigade(brigadeID, departmentID, models.BrigadeStatusInactive)}, nil
		},
		checkBrigadeReadinessFunc: func(ctx context.Context, id uuid.UUID, requireOnShift bool, roles []models.BrigadeMemberRole) ([]string, error) {
			if requireOnShift {
				t.Fatal("active readiness should not require shift")
			}
			return []string{"brigade has no active members"}, nil
		},
		setBrigadeStatusFunc: func(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error) {
			t.Fatal("repo should not set status")
			return nil, nil
		},
	}
	svc := NewBrigadeService(newTestRepo(mock), nil, zap.NewNop())

	result, err := svc.SetBrigadeStatus(context.Background(), &models.SetBrigadeStatusInput{
		BrigadeID:       brigadeID,
		Status:          models.BrigadeStatusActive,
		ActorRoles:      []string{"admin"},
		ActorUserID:     ptrUUID(uuid.New()),
		ChangedByUserID: nil,
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrBrigadeUnavailable) {
		t.Fatalf("expected brigade unavailable, got %v", err)
	}
}

func TestMemberService_AddBrigadeMember_Success(t *testing.T) {
	departmentID := uuid.New()
	brigadeID := uuid.New()
	userID := uuid.New()
	memberID := uuid.New()
	actorID := uuid.New()
	mock := &mockBrigadeRepo{
		getBrigadeByIDFunc: func(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
			return &models.GetBrigadeByIDResult{Brigade: testBrigade(brigadeID, departmentID, models.BrigadeStatusActive)}, nil
		},
		getBrigadeByUserIDFunc: func(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error) {
			return nil, models.ErrNotFound
		},
		addBrigadeMemberFunc: func(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error) {
			if in.ChangedByUserID == nil || *in.ChangedByUserID != actorID {
				t.Fatalf("expected changed_by_user_id %s, got %v", actorID, in.ChangedByUserID)
			}
			return &models.AddBrigadeMemberResult{Member: testMember(memberID, brigadeID, userID)}, nil
		},
	}
	svc := NewMemberServiceStruct(newTestRepo(mock), zap.NewNop())

	result, err := svc.AddBrigadeMember(context.Background(), &models.AddBrigadeMemberInput{
		BrigadeID:         brigadeID,
		UserID:            userID,
		Role:              models.BrigadeMemberRoleLead,
		ActorUserID:       &actorID,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Member.ID != memberID {
		t.Fatalf("expected member id %s, got %s", memberID, result.Member.ID)
	}
}

func TestMemberService_AddBrigadeMember_UserAlreadyActive(t *testing.T) {
	departmentID := uuid.New()
	brigadeID := uuid.New()
	userID := uuid.New()
	mock := &mockBrigadeRepo{
		getBrigadeByIDFunc: func(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
			return &models.GetBrigadeByIDResult{Brigade: testBrigade(brigadeID, departmentID, models.BrigadeStatusActive)}, nil
		},
		getBrigadeByUserIDFunc: func(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error) {
			return &models.GetBrigadeByUserIDResult{Member: testMember(uuid.New(), uuid.New(), userID)}, nil
		},
	}
	svc := NewMemberServiceStruct(newTestRepo(mock), zap.NewNop())

	result, err := svc.AddBrigadeMember(context.Background(), &models.AddBrigadeMemberInput{
		BrigadeID:         brigadeID,
		UserID:            userID,
		Role:              models.BrigadeMemberRoleLead,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrAlreadyExists) {
		t.Fatalf("expected already exists, got %v", err)
	}
}

func TestMemberService_RemoveBrigadeMember_LastActiveMember(t *testing.T) {
	departmentID := uuid.New()
	brigadeID := uuid.New()
	memberID := uuid.New()
	mock := &mockBrigadeRepo{
		getBrigadeByIDFunc: func(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
			return &models.GetBrigadeByIDResult{Brigade: testBrigade(brigadeID, departmentID, models.BrigadeStatusActive)}, nil
		},
		listBrigadeMembersFunc: func(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error) {
			return &models.ListBrigadeMembersResult{Members: []*models.BrigadeMember{testMember(memberID, brigadeID, uuid.New())}, Total: 1}, nil
		},
	}
	svc := NewMemberServiceStruct(newTestRepo(mock), zap.NewNop())

	result, err := svc.RemoveBrigadeMember(context.Background(), &models.RemoveBrigadeMemberInput{
		BrigadeID:         brigadeID,
		MemberID:          memberID,
		ActorDepartmentID: &departmentID,
		ActorRoles:        []string{"dispatcher"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrBrigadeUnavailable) {
		t.Fatalf("expected brigade unavailable, got %v", err)
	}
}

func TestSkillService_CreateSkill_AdminOnly(t *testing.T) {
	called := false
	mock := &mockBrigadeRepo{
		createSkillFunc: func(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error) {
			called = true
			return &models.CreateSkillResult{Skill: &models.Skill{ID: uuid.New(), Code: in.Code, Name: in.Name, Active: true}}, nil
		},
	}
	svc := NewSkillServiceStruct(newTestRepo(mock), zap.NewNop())

	result, err := svc.CreateSkill(context.Background(), &models.CreateSkillInput{
		Code:       "plumbing",
		Name:       "Plumbing",
		ActorRoles: []string{"dispatcher"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied, got %v", err)
	}
	if called {
		t.Fatal("repo should not be called")
	}
}

func TestSkillService_ListSkills_DispatcherAllowed(t *testing.T) {
	mock := &mockBrigadeRepo{
		listSkillsFunc: func(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error) {
			if in.Limit != models.DefaultLimit {
				t.Fatalf("expected normalized limit %d, got %d", models.DefaultLimit, in.Limit)
			}
			return &models.ListSkillsResult{Skills: []*models.Skill{{ID: uuid.New(), Code: "plumbing", Name: "Plumbing", Active: true}}, Total: 1}, nil
		},
	}
	svc := NewSkillServiceStruct(newTestRepo(mock), zap.NewNop())

	result, err := svc.ListSkills(context.Background(), &models.ListSkillsInput{ActorRoles: []string{"dispatcher"}})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected total 1, got %d", result.Total)
	}
}

func TestScheduleService_SetBrigadeSchedule_ArchivedDenied(t *testing.T) {
	departmentID := uuid.New()
	brigadeID := uuid.New()
	mock := &mockBrigadeRepo{
		getBrigadeByIDFunc: func(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
			return &models.GetBrigadeByIDResult{Brigade: testBrigade(brigadeID, departmentID, models.BrigadeStatusArchived)}, nil
		},
	}
	svc := NewScheduleServiceStruct(newTestRepo(mock), zap.NewNop())

	result, err := svc.SetBrigadeSchedule(context.Background(), &models.SetBrigadeScheduleInput{
		BrigadeID: brigadeID,
		Items: []*models.BrigadeScheduleItem{{
			DayOfWeek: 1,
			StartsAt:  "09:00",
			EndsAt:    "18:00",
			Timezone:  "UTC",
		}},
		ActorRoles: []string{"admin"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied, got %v", err)
	}
}

func TestZoneService_CreateBrigadeZone_DepartmentMismatch(t *testing.T) {
	departmentID := uuid.New()
	zoneDepartmentID := uuid.New()
	brigadeID := uuid.New()
	mock := &mockBrigadeRepo{
		getBrigadeByIDFunc: func(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error) {
			return &models.GetBrigadeByIDResult{Brigade: testBrigade(brigadeID, departmentID, models.BrigadeStatusActive)}, nil
		},
	}
	svc := NewZoneServiceStruct(newTestRepo(mock), zap.NewNop())

	result, err := svc.CreateBrigadeZone(context.Background(), &models.CreateBrigadeZoneInput{
		BrigadeID:    brigadeID,
		DepartmentID: zoneDepartmentID,
		Name:         "North",
		GeoJSON:      `{"type":"Polygon","coordinates":[]}`,
		ActorRoles:   []string{"admin"},
	})

	if result != nil {
		t.Fatal("expected nil result")
	}
	if !errors.Is(err, models.ErrPermissionDenied) {
		t.Fatalf("expected permission denied, got %v", err)
	}
}

func TestZoneService_CheckBrigadeCoversPoint_Success(t *testing.T) {
	brigadeID := uuid.New()
	mock := &mockBrigadeRepo{
		checkBrigadeCoversPointFunc: func(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error) {
			if in.Longitude != 37.62 || in.Latitude != 55.75 {
				t.Fatalf("unexpected coordinates: %f %f", in.Longitude, in.Latitude)
			}
			return &models.CheckBrigadeCoversPointResult{Covers: true}, nil
		},
	}
	svc := NewZoneServiceStruct(newTestRepo(mock), zap.NewNop())

	result, err := svc.CheckBrigadeCoversPoint(context.Background(), &models.CheckBrigadeCoversPointInput{
		BrigadeID: brigadeID,
		Longitude: 37.62,
		Latitude:  55.75,
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !result.Covers {
		t.Fatal("expected covers true")
	}
}

func TestPermissionHelper(t *testing.T) {
	departmentID := uuid.New()
	otherDepartmentID := uuid.New()

	tests := []struct {
		name              string
		roles             []string
		actorDepartmentID *uuid.UUID
		wantErr           bool
	}{
		{name: "admin without department", roles: []string{"admin"}, wantErr: false},
		{name: "dispatcher same department", roles: []string{"dispatcher"}, actorDepartmentID: &departmentID, wantErr: false},
		{name: "dispatcher missing department", roles: []string{"dispatcher"}, wantErr: true},
		{name: "dispatcher other department", roles: []string{"dispatcher"}, actorDepartmentID: &otherDepartmentID, wantErr: true},
		{name: "user denied", roles: []string{"user"}, actorDepartmentID: &departmentID, wantErr: true},
		{name: "nil roles denied", roles: nil, actorDepartmentID: &departmentID, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPermissionAndDepartmentForAdminAndDispatcher(zap.NewNop(), time.Now(), tt.roles, tt.actorDepartmentID, departmentID)
			if tt.wantErr && !errors.Is(err, models.ErrPermissionDenied) {
				t.Fatalf("expected permission denied, got %v", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func ptrUUID(id uuid.UUID) *uuid.UUID {
	return &id
}
