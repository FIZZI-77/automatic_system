package service

import (
	"context"

	"brigade/models"
	"brigade/src/core/repository"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	"go.uber.org/zap"
)

type BrigadeService interface {
	CreateBrigade(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error)
	GetBrigadeByID(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error)
	ListBrigades(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error)
	UpdateBrigade(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error)
	DeactivateBrigade(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error)
	ArchiveBrigade(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error)

	SetBrigadeStatus(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error)
	GetBrigadeStatusHistory(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error)

	GetAvailableBrigades(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error)
	CheckBrigadeCanHandleTicket(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error)
}

type MemberService interface {
	AddBrigadeMember(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error)
	RemoveBrigadeMember(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error)
	ChangeBrigadeMemberRole(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error)
	SetBrigadeMemberAvailability(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error)
	ListBrigadeMembers(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error)

	GetBrigadeMemberHistory(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error)
	GetBrigadeMemberStatusHistory(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error)
	GetBrigadeByUserID(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error)
}

type SkillService interface {
	CreateSkill(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error)
	UpdateSkill(ctx context.Context, in *models.UpdateSkillInput) (*models.UpdateSkillResult, error)
	DeactivateSkill(ctx context.Context, in *models.DeactivateSkillInput) (*models.DeactivateSkillResult, error)
	ListSkills(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error)

	AddBrigadeSkill(ctx context.Context, in *models.AddBrigadeSkillInput) (*models.AddBrigadeSkillResult, error)
	RemoveBrigadeSkill(ctx context.Context, in *models.RemoveBrigadeSkillInput) (*models.RemoveBrigadeSkillResult, error)
	ListBrigadeSkills(ctx context.Context, in *models.ListBrigadeSkillsInput) (*models.ListBrigadeSkillsResult, error)
}

type ScheduleService interface {
	SetBrigadeSchedule(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error)
	ListBrigadeSchedule(ctx context.Context, in *models.ListBrigadeScheduleInput) (*models.ListBrigadeScheduleResult, error)
}

type ZoneService interface {
	CreateBrigadeZone(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error)
	UpdateBrigadeZone(ctx context.Context, in *models.UpdateBrigadeZoneInput) (*models.UpdateBrigadeZoneResult, error)
	DeleteBrigadeZone(ctx context.Context, in *models.DeleteBrigadeZoneInput) (*models.DeleteBrigadeZoneResult, error)
	ListBrigadeZones(ctx context.Context, in *models.ListBrigadeZonesInput) (*models.ListBrigadeZonesResult, error)

	CheckBrigadeCoversPoint(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error)
	FindBrigadesByPoint(ctx context.Context, in *models.FindBrigadesByPointInput) (*models.FindBrigadesByPointResult, error)
}

type Service struct {
	BrigadeService
	MemberService
	SkillService
	ScheduleService
	ZoneService
}

func NewService(repo *repository.Repo, departmentClient departmentv1.DepartmentServiceClient, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Service{
		BrigadeService:  NewBrigadeService(repo, departmentClient, logger),
		MemberService:   NewMemberServiceStruct(repo, logger),
		SkillService:    NewSkillServiceStruct(repo, logger),
		ScheduleService: NewScheduleServiceStruct(repo, logger),
		ZoneService:     NewZoneServiceStruct(repo, logger),
	}
}
