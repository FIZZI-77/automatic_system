package service

import (
	"context"

	"brigade/models"
	"brigade/src/core/repository"

	departmentv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/department/v1"
	profilev1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/profile/v1"
	"go.uber.org/zap"
)

type BrigadeService interface {
	// CreateBrigade создаёт бригаду после проверки прав и активности ведомства в Department Service.
	CreateBrigade(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error)
	// GetBrigadeByID возвращает бригаду администратору, диспетчеру её ведомства или активному участнику.
	GetBrigadeByID(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error)
	// ListBrigades возвращает страницу бригад; для диспетчера подставляет его ведомство в in.
	ListBrigades(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error)
	// UpdateBrigade проверяет запрос и доступ и меняет заданные поля бригады.
	UpdateBrigade(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error)
	// DeactivateBrigade проверяет доступ и переводит бригаду в INACTIVE с заполнением автора изменения.
	DeactivateBrigade(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error)
	// ArchiveBrigade проверяет доступ и переводит бригаду в ARCHIVED с заполнением автора изменения.
	ArchiveBrigade(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error)

	// SetBrigadeStatus проверяет доступ и готовность к ACTIVE или AVAILABLE и меняет статус.
	SetBrigadeStatus(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error)
	// GetBrigadeStatusHistory возвращает историю статусов администратору или диспетчеру ведомства бригады.
	GetBrigadeStatusHistory(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error)

	// GetAvailableBrigades проверяет и нормализует запрос и подбирает доступные бригады по требованиям.
	GetAvailableBrigades(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error)
	// CheckBrigadeCanHandleTicket возвращает возможность назначения на заявку и причины отказа.
	CheckBrigadeCanHandleTicket(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error)
}

type MemberService interface {
	// AddBrigadeMember проверяет доступ и членство, при настроенном клиенте загружает профиль и навыки в in.
	AddBrigadeMember(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error)
	// RemoveBrigadeMember исключает участника после проверки доступа и сохранения необходимого активного состава.
	RemoveBrigadeMember(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error)
	// ChangeBrigadeMemberRole меняет роль участника неархивной бригады после проверки доступа.
	ChangeBrigadeMemberRole(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error)
	// SetBrigadeMemberAvailability меняет доступность участника неархивной бригады после проверки доступа.
	SetBrigadeMemberAvailability(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error)
	// ListBrigadeMembers возвращает состав администратору, диспетчеру ведомства или активному участнику бригады.
	ListBrigadeMembers(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error)

	// GetBrigadeMemberHistory возвращает историю состава неархивной бригады после проверки доступа.
	GetBrigadeMemberHistory(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error)
	// GetBrigadeMemberStatusHistory возвращает историю доступности участников после проверки доступа.
	GetBrigadeMemberStatusHistory(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error)
	// GetBrigadeByUserID возвращает последнее членство пользователя и бригаду с учётом OnlyActive.
	GetBrigadeByUserID(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error)
}

type SkillService interface {
	// CreateSkill проверяет запрос и создаёт навык каталога для администратора.
	CreateSkill(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error)
	// UpdateSkill проверяет запрос и меняет заданные поля навыка для администратора.
	UpdateSkill(ctx context.Context, in *models.UpdateSkillInput) (*models.UpdateSkillResult, error)
	// DeactivateSkill выключает навык каталога для администратора.
	DeactivateSkill(ctx context.Context, in *models.DeactivateSkillInput) (*models.DeactivateSkillResult, error)
	// ListSkills возвращает страницу каталога администратору или диспетчеру, нормализуя пагинацию в in.
	ListSkills(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error)

	// AddBrigadeSkill связывает навык с неархивной бригадой для администратора или диспетчера её ведомства.
	AddBrigadeSkill(ctx context.Context, in *models.AddBrigadeSkillInput) (*models.AddBrigadeSkillResult, error)
	// RemoveBrigadeSkill выключает связь навыка с неархивной бригадой после проверки доступа.
	RemoveBrigadeSkill(ctx context.Context, in *models.RemoveBrigadeSkillInput) (*models.RemoveBrigadeSkillResult, error)
	// ListBrigadeSkills возвращает навыки неархивной бригады администратору или диспетчеру её ведомства.
	ListBrigadeSkills(ctx context.Context, in *models.ListBrigadeSkillsInput) (*models.ListBrigadeSkillsResult, error)
}

type ScheduleService interface {
	// SetBrigadeSchedule проверяет запрос и заменяет расписание для администратора или диспетчера ведомства бригады.
	SetBrigadeSchedule(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error)
	// ListBrigadeSchedule возвращает расписание после проверки прав, включая доступ активного участника своей бригады.
	ListBrigadeSchedule(ctx context.Context, in *models.ListBrigadeScheduleInput) (*models.ListBrigadeScheduleResult, error)
}

type ZoneService interface {
	// CreateBrigadeZone создаёт зону неархивной бригады с проверкой совпадения ведомств и прав.
	CreateBrigadeZone(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error)
	// UpdateBrigadeZone меняет заданные поля зоны после проверки доступа к неархивной бригаде.
	UpdateBrigadeZone(ctx context.Context, in *models.UpdateBrigadeZoneInput) (*models.UpdateBrigadeZoneResult, error)
	// DeleteBrigadeZone деактивирует зону после проверки доступа к неархивной бригаде.
	DeleteBrigadeZone(ctx context.Context, in *models.DeleteBrigadeZoneInput) (*models.DeleteBrigadeZoneResult, error)
	// ListBrigadeZones возвращает зоны неархивной бригады администратору или диспетчеру её ведомства.
	ListBrigadeZones(ctx context.Context, in *models.ListBrigadeZonesInput) (*models.ListBrigadeZonesResult, error)

	// CheckBrigadeCoversPoint проверяет координаты и возвращает покрытие точки активными зонами бригады.
	CheckBrigadeCoversPoint(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error)
	// FindBrigadesByPoint проверяет и нормализует in и возвращает страницу бригад, покрывающих точку.
	FindBrigadesByPoint(ctx context.Context, in *models.FindBrigadesByPointInput) (*models.FindBrigadesByPointResult, error)
}

type Service struct {
	BrigadeService
	MemberService
	SkillService
	ScheduleService
	ZoneService
}

// NewService объединяет операции бригад, состава, навыков, расписаний и зон
// без клиента Profile Service. nil logger отключает вывод журнала.
func NewService(repo *repository.Repo, departmentClient departmentv1.DepartmentServiceClient, logger *zap.Logger) *Service {
	return NewServiceWithProfile(repo, departmentClient, nil, logger)
}

// NewServiceWithProfile объединяет операции бригад с клиентами ведомств и профилей.
// nil logger заменяет журналом без вывода; profileClient передаётся сервису состава.
func NewServiceWithProfile(repo *repository.Repo, departmentClient departmentv1.DepartmentServiceClient, profileClient profilev1.ProfileServiceClient, logger *zap.Logger) *Service {

	if logger == nil {
		logger = zap.NewNop()
	}

	return &Service{
		BrigadeService:  NewBrigadeService(repo, departmentClient, logger),
		MemberService:   NewMemberServiceStructWithProfile(repo, profileClient, logger),
		SkillService:    NewSkillServiceStruct(repo, logger),
		ScheduleService: NewScheduleServiceStruct(repo, logger),
		ZoneService:     NewZoneServiceStruct(repo, logger),
	}
}
