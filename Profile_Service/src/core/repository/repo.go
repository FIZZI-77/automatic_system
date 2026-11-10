package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"profile/models"
)

type UserProfileRepository interface {
	// CreateUserProfile сохраняет профиль пользователя и событие создания в одной транзакции.
	CreateUserProfile(ctx context.Context, in *models.CreateUserProfileInput) (*models.CreateUserProfileResult, error)
	// UpdateUserProfile меняет заданные поля, обрабатывает флаги очистки и сохраняет событие outbox.
	UpdateUserProfile(ctx context.Context, in *models.UpdateUserProfileInput) (*models.UpdateUserProfileResult, error)
	// GetUserProfileByID возвращает профиль по ID либо ErrNotFound.
	GetUserProfileByID(ctx context.Context, in *models.GetUserProfileByIDInput) (*models.GetUserProfileByIDResult, error)
	// GetUserProfileByUserID возвращает профиль по ID пользователя либо ErrNotFound.
	GetUserProfileByUserID(ctx context.Context, in *models.GetUserProfileByUserIDInput) (*models.GetUserProfileByUserIDResult, error)
	// ListUserProfiles возвращает страницу с поиском по имени и телефону и общий счётчик.
	ListUserProfiles(ctx context.Context, in *models.ListUserProfilesInput) (*models.ListUserProfilesResult, error)
}

type WorkProfileRepository interface {
	// CreateWorkProfile сохраняет ACTIVE-профиль, начальную историю и событие outbox в одной транзакции.
	CreateWorkProfile(ctx context.Context, in *models.CreateWorkProfileInput) (*models.CreateWorkProfileResult, error)
	// UpdateWorkProfile сохраняет заданные должность и табельный номер с поддержкой очистки и событием outbox.
	UpdateWorkProfile(ctx context.Context, in *models.UpdateWorkProfileInput) (*models.UpdateWorkProfileResult, error)
	// GetWorkProfileByID возвращает рабочий профиль с пользователем по ID либо ErrNotFound.
	GetWorkProfileByID(ctx context.Context, in *models.GetWorkProfileByIDInput) (*models.GetWorkProfileByIDResult, error)
	// GetWorkProfileByUserID возвращает рабочий профиль с пользователем по UserID либо ErrNotFound.
	GetWorkProfileByUserID(ctx context.Context, in *models.GetWorkProfileByUserIDInput) (*models.GetWorkProfileByUserIDResult, error)
	// ListWorkProfiles возвращает страницу рабочих профилей по фильтрам и отдельный общий счётчик.
	ListWorkProfiles(ctx context.Context, in *models.ListWorkProfilesInput) (*models.ListWorkProfilesResult, error)
	// DeactivateWorkProfile сохраняет INACTIVE, историю и outbox; повторная деактивация не создаёт новых записей.
	DeactivateWorkProfile(ctx context.Context, in *models.DeactivateWorkProfileInput) (*models.DeactivateWorkProfileResult, error)
	// ChangeWorkProfileDepartment сохраняет ведомство и событие, если новое ведомство отличается от текущего.
	ChangeWorkProfileDepartment(ctx context.Context, in *models.ChangeWorkProfileDepartmentInput) (*models.ChangeWorkProfileDepartmentResult, error)
	// SetWorkProfileStatus блокирует профиль и сохраняет разрешённую смену статуса с историей и outbox.
	SetWorkProfileStatus(ctx context.Context, in *models.SetWorkProfileStatusInput) (*models.SetWorkProfileStatusResult, error)
	// GetWorkProfileStatusHistory возвращает страницу истории от новых записей к старым и общий счётчик.
	GetWorkProfileStatusHistory(ctx context.Context, in *models.GetWorkProfileStatusHistoryInput) (*models.GetWorkProfileStatusHistoryResult, error)
	// ResolveWorkingDepartment возвращает рабочее ведомство пользователя и CanOperate для ACTIVE или ON_SHIFT.
	ResolveWorkingDepartment(ctx context.Context, in *models.ResolveWorkingDepartmentInput) (*models.ResolveWorkingDepartmentResult, error)
	// CheckProfileCanJoinBrigade возвращает решение по статусу и ведомству; отсутствие профиля даёт отказ без ошибки.
	CheckProfileCanJoinBrigade(ctx context.Context, in *models.CheckProfileCanJoinBrigadeInput) (*models.CheckProfileCanJoinBrigadeResult, error)
}

type CertificationRepository interface {
	// CreateCertificationType сохраняет тип сертификата с событием создания в одной транзакции.
	CreateCertificationType(ctx context.Context, in *models.CreateCertificationTypeInput) (*models.CreateCertificationTypeResult, error)
	// UpdateCertificationType меняет заданные поля типа с флагами очистки и записывает outbox.
	UpdateCertificationType(ctx context.Context, in *models.UpdateCertificationTypeInput) (*models.UpdateCertificationTypeResult, error)
	// GetCertificationTypeByID возвращает тип, включая неактивный, либо ErrNotFound.
	GetCertificationTypeByID(ctx context.Context, id uuid.UUID) (*models.CertificationType, error)
	// ListCertificationTypes возвращает страницу типов по активности и поиску с общим счётчиком.
	ListCertificationTypes(ctx context.Context, in *models.ListCertificationTypesInput) (*models.ListCertificationTypesResult, error)
	// AddCertificationTypeSkill создаёт или восстанавливает связь типа с навыком и записывает outbox.
	AddCertificationTypeSkill(ctx context.Context, in *models.AddCertificationTypeSkillInput) (*models.AddCertificationTypeSkillResult, error)
	// RemoveCertificationTypeSkill деактивирует активную связь и записывает событие, не меняя выданные навыки.
	RemoveCertificationTypeSkill(ctx context.Context, in *models.RemoveCertificationTypeSkillInput) error
	// ListCertificationTypeSkills возвращает связи типа с навыками, учитывая ActiveOnly.
	ListCertificationTypeSkills(ctx context.Context, in *models.ListCertificationTypeSkillsInput) (*models.ListCertificationTypeSkillsResult, error)
	// UploadWorkProfileCertification сохраняет сертификат PENDING и событие загрузки в одной транзакции.
	UploadWorkProfileCertification(ctx context.Context, in *models.UploadWorkProfileCertificationInput) (*models.UploadWorkProfileCertificationResult, error)
	// VerifyWorkProfileCertification подтверждает PENDING, выдаёт навыки типа и записывает outbox.
	// Повтор VERIFIED возвращает прежние назначения без изменений.
	VerifyWorkProfileCertification(ctx context.Context, in *models.VerifyWorkProfileCertificationInput) (*models.VerifyWorkProfileCertificationResult, error)
	// RejectWorkProfileCertification отклоняет PENDING с причиной и outbox; повтор REJECTED не меняет запись.
	RejectWorkProfileCertification(ctx context.Context, in *models.RejectWorkProfileCertificationInput) (*models.RejectWorkProfileCertificationResult, error)
	// RevokeWorkProfileCertification отзывает сертификат и его активные назначения с событиями outbox.
	RevokeWorkProfileCertification(ctx context.Context, in *models.RevokeWorkProfileCertificationInput) (*models.RevokeWorkProfileCertificationResult, error)
	// ExpireWorkProfileCertifications обрабатывает пакет истёкших VERIFIED-сертификатов и отзывает их навыки.
	ExpireWorkProfileCertifications(ctx context.Context, in *models.ExpireWorkProfileCertificationsInput) (*models.ExpireWorkProfileCertificationsResult, error)
	// ListWorkProfileCertifications возвращает страницу сертификатов профиля по типу и статусу с общим счётчиком.
	ListWorkProfileCertifications(ctx context.Context, in *models.ListWorkProfileCertificationsInput) (*models.ListWorkProfileCertificationsResult, error)
	// GrantManualWorkProfileSkill сохраняет ручное назначение и outbox, отклоняя INACTIVE/SUSPENDED-профиль.
	GrantManualWorkProfileSkill(ctx context.Context, in *models.GrantManualWorkProfileSkillInput) (*models.GrantManualWorkProfileSkillResult, error)
	// RevokeWorkProfileSkillGrant выключает активное назначение с причиной и outbox; повтор даёт ErrNotFound.
	RevokeWorkProfileSkillGrant(ctx context.Context, in *models.RevokeWorkProfileSkillGrantInput) (*models.RevokeWorkProfileSkillGrantResult, error)
	// ListEffectiveWorkProfileSkills возвращает действующие назначения ACTIVE/ON_SHIFT-профиля с проверкой источников.
	ListEffectiveWorkProfileSkills(ctx context.Context, in *models.ListEffectiveWorkProfileSkillsInput) (*models.ListEffectiveWorkProfileSkillsResult, error)
	// BatchListEffectiveWorkProfileSkills возвращает действующие назначения с ключом для каждого запрошенного профиля.
	BatchListEffectiveWorkProfileSkills(ctx context.Context, in *models.BatchListEffectiveWorkProfileSkillsInput) (*models.BatchListEffectiveWorkProfileSkillsResult, error)
	// CheckWorkProfileHasSkills возвращает решение и ID требуемых навыков без действующих назначений.
	CheckWorkProfileHasSkills(ctx context.Context, in *models.CheckWorkProfileHasSkillsInput) (*models.CheckWorkProfileHasSkillsResult, error)
}

type Repository struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
	UserProfileRepository
	WorkProfileRepository
	CertificationRepository
}

// NewRepository объединяет хранилища пользовательских и рабочих профилей и квалификаций.
// При nil pools.Read использует pools.Write для чтения.
func NewRepository(pools DBPools) *Repository {

	if pools.Read == nil {
		pools.Read = pools.Write
	}

	return &Repository{
		writePool:               pools.Write,
		readPool:                pools.Read,
		UserProfileRepository:   NewUserProfileRepository(pools.Write, pools.Read),
		WorkProfileRepository:   NewWorkProfileRepository(pools.Write, pools.Read),
		CertificationRepository: NewCertificationRepository(pools.Write, pools.Read),
	}
}
