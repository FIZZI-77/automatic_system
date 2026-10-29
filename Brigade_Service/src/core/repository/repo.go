package repository

import (
	"brigade/models"
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type BrigadeRepo interface {
	// CreateBrigade сохраняет бригаду и outbox атомарно; дубликат имени даёт ErrAlreadyExists.
	CreateBrigade(ctx context.Context, in *models.CreateBrigadeInput) (*models.CreateBrigadeResult, error)
	// GetBrigadeByID читает бригаду любого статуса по ID либо возвращает ErrNotFound.
	GetBrigadeByID(ctx context.Context, in *models.GetBrigadeByIDInput) (*models.GetBrigadeByIDResult, error)
	// ListBrigades возвращает страницу по фильтрам и сортировке и отдельный общий счётчик.
	ListBrigades(ctx context.Context, in *models.ListBrigadesInput) (*models.ListBrigadesResult, error)
	// UpdateBrigade меняет заданные поля бригады и записывает outbox одной транзакцией.
	UpdateBrigade(ctx context.Context, in *models.UpdateBrigadeInput) (*models.UpdateBrigadeResult, error)
	// DeactivateBrigade ставит INACTIVE и время деактивации, завершает смену и пишет историю и outbox.
	DeactivateBrigade(ctx context.Context, in *models.DeactivateBrigadeInput) (*models.DeactivateBrigadeResult, error)
	// ArchiveBrigade ставит ARCHIVED и время архивации, завершает смену и пишет историю и outbox.
	ArchiveBrigade(ctx context.Context, in *models.ArchiveBrigadeInput) (*models.ArchiveBrigadeResult, error)
	// SetBrigadeStatus атомарно меняет статус с историей, outbox и синхронизацией смены.
	SetBrigadeStatus(ctx context.Context, in *models.SetBrigadeStatusInput) (*models.SetBrigadeStatusResult, error)
	// GetBrigadeStatusHistory возвращает страницу истории от новых записей к старым с общим счётчиком.
	GetBrigadeStatusHistory(ctx context.Context, in *models.GetBrigadeStatusHistoryInput) (*models.GetBrigadeStatusHistoryResult, error)
	// CheckBrigadeReadiness возвращает причины неготовности состава и ролей; requireOnShift добавляет смену и доступность.
	CheckBrigadeReadiness(ctx context.Context, brigadeID uuid.UUID, requireOnShift bool, requiredRoles []models.BrigadeMemberRole) ([]string, error)
	// GetAvailableBrigades подбирает доступные бригады по составу, смене, ролям, навыкам и необязательным координатам.
	GetAvailableBrigades(ctx context.Context, in *models.GetAvailableBrigadesInput) (*models.GetAvailableBrigadesResult, error)
	// CheckBrigadeCanHandleTicket возвращает возможность назначения по ведомству, статусу, составу, смене, зоне и навыкам.
	CheckBrigadeCanHandleTicket(ctx context.Context, in *models.CheckBrigadeCanHandleTicketInput) (*models.CheckBrigadeCanHandleTicketResult, error)
}

type MemberRepo interface {
	// AddBrigadeMember атомарно сохраняет участника, начальные навыки, историю и outbox.
	AddBrigadeMember(ctx context.Context, in *models.AddBrigadeMemberInput) (*models.AddBrigadeMemberResult, error)
	// RemoveBrigadeMember выключает членство и навыки с записью времени выхода, истории и outbox.
	RemoveBrigadeMember(ctx context.Context, in *models.RemoveBrigadeMemberInput) (*models.RemoveBrigadeMemberResult, error)
	// ChangeBrigadeMemberRole меняет роль участника с историей и outbox в одной транзакции.
	ChangeBrigadeMemberRole(ctx context.Context, in *models.ChangeBrigadeMemberRoleInput) (*models.ChangeBrigadeMemberRoleResult, error)
	// SetBrigadeMemberAvailability меняет доступность и её временную метку с историей и outbox.
	SetBrigadeMemberAvailability(ctx context.Context, in *models.SetBrigadeMemberAvailabilityInput) (*models.SetBrigadeMemberAvailabilityResult, error)
	// ListBrigadeMembers возвращает страницу состава по активности, роли и доступности с общим счётчиком.
	ListBrigadeMembers(ctx context.Context, in *models.ListBrigadeMembersInput) (*models.ListBrigadeMembersResult, error)
	// GetBrigadeMemberHistory возвращает историю состава с необязательным фильтром участника и общим счётчиком.
	GetBrigadeMemberHistory(ctx context.Context, in *models.GetBrigadeMemberHistoryInput) (*models.GetBrigadeMemberHistoryResult, error)
	// GetBrigadeMemberStatusHistory возвращает историю доступности с необязательным фильтром участника и общим счётчиком.
	GetBrigadeMemberStatusHistory(ctx context.Context, in *models.GetBrigadeMemberStatusHistoryInput) (*models.GetBrigadeMemberStatusHistoryResult, error)
	// GetBrigadeByUserID возвращает последнее членство пользователя и бригаду; OnlyActive фильтрует членство.
	GetBrigadeByUserID(ctx context.Context, in *models.GetBrigadeByUserIDInput) (*models.GetBrigadeByUserIDResult, error)
}

type SkillRepo interface {
	// CreateSkill сохраняет навык и событие outbox; дубликат кода даёт ErrAlreadyExists.
	CreateSkill(ctx context.Context, in *models.CreateSkillInput) (*models.CreateSkillResult, error)
	// UpdateSkill меняет ненулевые поля навыка и записывает событие outbox.
	UpdateSkill(ctx context.Context, in *models.UpdateSkillInput) (*models.UpdateSkillResult, error)
	// DeactivateSkill выключает навык и записывает outbox, сохраняя строку и связи бригад.
	DeactivateSkill(ctx context.Context, in *models.DeactivateSkillInput) (*models.DeactivateSkillResult, error)
	// ListSkills возвращает страницу каталога по активности и поиску с общим счётчиком.
	ListSkills(ctx context.Context, in *models.ListSkillsInput) (*models.ListSkillsResult, error)
	// AddBrigadeSkill вставляет связь бригады с навыком и событие; активный дубликат даёт ErrAlreadyExists.
	AddBrigadeSkill(ctx context.Context, in *models.AddBrigadeSkillInput) (*models.AddBrigadeSkillResult, error)
	// RemoveBrigadeSkill выключает связь по паре бригада–навык и записывает событие outbox.
	RemoveBrigadeSkill(ctx context.Context, in *models.RemoveBrigadeSkillInput) (*models.RemoveBrigadeSkillResult, error)
	// ListBrigadeSkills возвращает связи с данными навыков по коду; Active фильтрует активность связи.
	ListBrigadeSkills(ctx context.Context, in *models.ListBrigadeSkillsInput) (*models.ListBrigadeSkillsResult, error)
}

type ScheduleRepo interface {
	// SetBrigadeSchedule транзакционно деактивирует прежнее расписание, вставляет новые элементы и записывает outbox.
	SetBrigadeSchedule(ctx context.Context, in *models.SetBrigadeScheduleInput) (*models.SetBrigadeScheduleResult, error)
	// ListBrigadeSchedule возвращает расписание по дню недели и времени начала с фильтром активности.
	ListBrigadeSchedule(ctx context.Context, in *models.ListBrigadeScheduleInput) (*models.ListBrigadeScheduleResult, error)
}

type ZoneRepo interface {
	// GetBrigadeZoneByID возвращает зону по ID, включая неактивную, либо ErrNotFound.
	GetBrigadeZoneByID(ctx context.Context, zoneID uuid.UUID) (*models.BrigadeZone, error)
	// CreateBrigadeZone сохраняет зону из GeoJSON и событие создания в одной транзакции.
	CreateBrigadeZone(ctx context.Context, in *models.CreateBrigadeZoneInput) (*models.CreateBrigadeZoneResult, error)
	// UpdateBrigadeZone меняет заданные поля зоны и записывает outbox; nil поля сохраняет.
	UpdateBrigadeZone(ctx context.Context, in *models.UpdateBrigadeZoneInput) (*models.UpdateBrigadeZoneResult, error)
	// DeleteBrigadeZone деактивирует зону и записывает outbox без удаления строки.
	DeleteBrigadeZone(ctx context.Context, in *models.DeleteBrigadeZoneInput) (*models.DeleteBrigadeZoneResult, error)
	// ListBrigadeZones возвращает зоны бригады с фильтром активности по приоритету и времени создания DESC.
	ListBrigadeZones(ctx context.Context, in *models.ListBrigadeZonesInput) (*models.ListBrigadeZonesResult, error)
	// CheckBrigadeCoversPoint возвращает покрытие точки и совпавшие активные зоны, включая границу.
	CheckBrigadeCoversPoint(ctx context.Context, in *models.CheckBrigadeCoversPointInput) (*models.CheckBrigadeCoversPointResult, error)
	// FindBrigadesByPoint возвращает страницу бригад с зоной покрытия и заданными требованиями с общим счётчиком.
	FindBrigadesByPoint(ctx context.Context, in *models.FindBrigadesByPointInput) (*models.FindBrigadesByPointResult, error)
}

type Repository struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
	BrigadeRepo
	MemberRepo
	SkillRepo
	ScheduleRepo
	ZoneRepo
}

type Repo = Repository

// NewRepository объединяет хранилища бригад, состава, навыков, расписаний и зон.
// При nil pools.Read использует pools.Write для чтения.
func NewRepository(pools DBPools) *Repository {

	if pools.Read == nil {
		pools.Read = pools.Write
	}

	return &Repository{
		writePool:    pools.Write,
		readPool:     pools.Read,
		BrigadeRepo:  NewBrigadeRepo(pools.Write, pools.Read),
		MemberRepo:   NewMemberRepo(pools.Write, pools.Read),
		SkillRepo:    NewSkillRepo(pools.Write, pools.Read),
		ScheduleRepo: NewScheduleRepo(pools.Write, pools.Read),
		ZoneRepo:     NewZoneRepo(pools.Write, pools.Read),
	}
}
