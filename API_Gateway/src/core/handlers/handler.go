package handlers

import (
	"gateway/src/core/middleware"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
)

func handleGRPCError(c *gin.Context, err error) {
	st, ok := status.FromError(err)
	if !ok {
		writeAPIError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Внутренняя ошибка сервера")
		return
	}

	switch st.Code() {
	case codes.InvalidArgument:
		writeAPIError(c, http.StatusBadRequest, "INVALID_ARGUMENT", "Проверьте введённые данные")
	case codes.Unauthenticated:
		writeAPIError(c, http.StatusUnauthorized, "UNAUTHENTICATED", "Необходимо войти в систему заново")
	case codes.PermissionDenied:
		writeAPIError(c, http.StatusForbidden, "PERMISSION_DENIED", "Недостаточно прав для выполнения действия")
	case codes.NotFound:
		writeAPIError(c, http.StatusNotFound, "NOT_FOUND", "Запрошенные данные не найдены")
	case codes.AlreadyExists:
		writeAPIError(c, http.StatusConflict, "ALREADY_EXISTS", "Такая запись уже существует")
	case codes.Aborted, codes.FailedPrecondition:
		writeAPIError(c, http.StatusConflict, "INVALID_STATE", "Действие невозможно в текущем состоянии")
	case codes.DeadlineExceeded:
		writeAPIError(c, http.StatusGatewayTimeout, "UPSTREAM_TIMEOUT", "Сервис не успел ответить. Попробуйте ещё раз")
	case codes.Canceled:
		writeAPIError(c, http.StatusRequestTimeout, "REQUEST_CANCELED", "Запрос был отменён. Попробуйте ещё раз")
	case codes.Unavailable:
		writeAPIError(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Сервис временно недоступен")
	default:
		writeAPIError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Внутренняя ошибка сервера")
	}
}

func writeAPIError(c *gin.Context, statusCode int, code, message string) {
	c.JSON(statusCode, gin.H{"code": code, "error": message})
}

type Handler struct {
	authHandler         *AuthHandler
	ticketHandler       *TicketHandler
	departmentHandler   *DepartmentHandler
	brigadeHandler      *BrigadeHandler
	profileHandler      *ProfileHandler
	locationHandler     *LocationHandler
	routingHandler      *RoutingHandler
	dispatchHandler     *DispatchHandler
	fileHandler         *FileHandler
	slaHandler          *SLAHandler
	notificationHandler *NotificationHandler
	auditHandler        *AuditHandler
	analyticsHandler    *AnalyticsHandler
	reportHandler       *ReportHandler
	assetHandler        *AssetHandler
	authMiddleware      *middleware.AuthMiddleware
	rateLimiter         *middleware.RedisRateLimiter
}

func NewHandler(
	authHandler *AuthHandler,
	ticketHandler *TicketHandler,
	departmentHandler *DepartmentHandler,
	brigadeHandler *BrigadeHandler,
	profileHandler *ProfileHandler,
	locationHandler *LocationHandler,
	routingHandler *RoutingHandler,
	dispatchHandler *DispatchHandler,
	fileHandler *FileHandler,
	slaHandler *SLAHandler,
	notificationHandler *NotificationHandler,
	auditHandler *AuditHandler,
	analyticsHandler *AnalyticsHandler,
	reportHandler *ReportHandler,
	assetHandler *AssetHandler,
	authMiddleware *middleware.AuthMiddleware,
	rateLimiter *middleware.RedisRateLimiter,
) *Handler {
	return &Handler{
		authHandler:         authHandler,
		ticketHandler:       ticketHandler,
		departmentHandler:   departmentHandler,
		brigadeHandler:      brigadeHandler,
		profileHandler:      profileHandler,
		locationHandler:     locationHandler,
		routingHandler:      routingHandler,
		dispatchHandler:     dispatchHandler,
		fileHandler:         fileHandler,
		slaHandler:          slaHandler,
		notificationHandler: notificationHandler,
		auditHandler:        auditHandler,
		analyticsHandler:    analyticsHandler,
		reportHandler:       reportHandler,
		assetHandler:        assetHandler,
		authMiddleware:      authMiddleware,
		rateLimiter:         rateLimiter,
	}
}

func (h *Handler) InitRouters() *gin.Engine {

	router := gin.New()
	allowedOrigins := map[string]struct{}{}
	for _, origin := range strings.Split(envOrDefault("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"), ",") {
		if value := strings.TrimSpace(origin); value != "" {
			allowedOrigins[value] = struct{}{}
		}
	}
	router.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if _, allowed := allowedOrigins[origin]; allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-Request-ID")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Expose-Headers", "X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining")
			c.Header("Vary", "Origin")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	router.Use(middleware.RequestID())
	router.Use(middleware.IdempotencyKey())
	router.Use(h.rateLimiter.Middleware(middleware.RateLimitConfig{
		Name:   "global",
		Limit:  300,
		Burst:  100,
		Window: time.Minute,
		SkipFunc: func(c *gin.Context) bool {
			return c.Request.URL.Path == "/health" || c.Request.URL.Path == "/livez" || c.Request.URL.Path == "/readyz"
		},
	}))
	router.Use(middleware.RequestLogger())
	router.Use(gin.Recovery())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})
	router.GET("/livez", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "alive"})
	})
	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	publicAuth := router.Group("/auth")
	publicAuth.Use(h.rateLimiter.Middleware(middleware.RateLimitConfig{
		Name:   "public-auth",
		Limit:  20,
		Burst:  10,
		Window: time.Minute,
		KeyFunc: func(c *gin.Context) string {
			return c.ClientIP() + ":" + c.Request.URL.Path
		},
	}))
	{
		publicAuth.POST("/register", h.authHandler.Register)
		publicAuth.POST("/login", h.authHandler.Login)
		publicAuth.POST("/refresh", h.authHandler.Refresh)
		publicAuth.POST("/verify-email", h.authHandler.VerifyEmail)
		publicAuth.POST("/request-password-reset", h.authHandler.RequestPasswordReset)
		publicAuth.POST("/reset-password", h.authHandler.ResetPassword)
	}

	privateAuth := router.Group("/auth")
	privateAuth.Use(h.authMiddleware.Handle())
	privateAuth.Use(h.rateLimiter.Middleware(middleware.RateLimitConfig{
		Name:   "private-auth",
		Limit:  30,
		Burst:  10,
		Window: time.Minute,
		KeyFunc: func(c *gin.Context) string {
			userID := c.GetString("user_id")
			if userID == "" {
				userID = c.ClientIP()
			}
			return userID + ":" + c.Request.URL.Path
		},
	}))
	{
		privateAuth.POST("/logout", h.authHandler.Logout)
		privateAuth.POST("/logout-all", h.authHandler.LogoutAll)
		privateAuth.GET("/me", h.authHandler.GetUserAuthInfo)
		privateAuth.POST("/change-password", h.authHandler.ChangePassword)
		privateAuth.POST("/send-verification-email", h.authHandler.SendVerificationEmail)
	}

	router.GET("/.well-known/jwks.json", h.authHandler.GetJWKS)

	privateTickets := router.Group("/tickets")
	privateTickets.Use(h.authMiddleware.Handle())
	{
		privateTickets.POST("/create", h.ticketHandler.CreateTicket)
		privateTickets.POST("/get", h.ticketHandler.GetTicket)
		privateTickets.POST("/list", h.ticketHandler.ListTicket)
		privateTickets.POST("/update", h.ticketHandler.UpdateTicket)
		privateTickets.POST("/assign-brigade", h.ticketHandler.AssignBrigade)
		privateTickets.POST("/change-status", h.ticketHandler.ChangeTicketStatus)
		privateTickets.POST("/cancel", h.ticketHandler.CancelTicket)
		privateTickets.POST("/complete", h.ticketHandler.CompleteTicket)
		privateTickets.POST("/status-history", h.ticketHandler.GetTicketStatusHistory)
		privateTickets.POST("/reports/create", h.ticketHandler.CreateWorkReport)
		privateTickets.POST("/reports/list", h.ticketHandler.ListWorkReports)
	}

	privateFiles := router.Group("/files")
	privateFiles.Use(h.authMiddleware.Handle())
	{
		privateFiles.POST("/uploads/create", h.fileHandler.CreateUpload)
		privateFiles.POST("/uploads/confirm", h.fileHandler.ConfirmUpload)
		privateFiles.POST("/link", h.fileHandler.LinkFile)
		privateFiles.POST("/download-url", h.fileHandler.GetDownloadURL)
		privateFiles.POST("/list", h.fileHandler.ListResourceFiles)
		privateFiles.POST("/delete", h.fileHandler.DeleteFile)
	}
	privateSLA := router.Group("/sla")
	privateSLA.Use(h.authMiddleware.Handle())
	{
		privateSLA.POST("/rules/create", h.slaHandler.CreateRule)
		privateSLA.POST("/rules/update", h.slaHandler.UpdateRule)
		privateSLA.POST("/rules/delete", h.slaHandler.DeleteRule)
		privateSLA.POST("/rules/get", h.slaHandler.GetRule)
		privateSLA.POST("/rules/list", h.slaHandler.ListRules)
		privateSLA.POST("/tickets/get", h.slaHandler.GetTicketSLA)
		privateSLA.POST("/tickets/list", h.slaHandler.ListTicketSLAs)
		privateSLA.POST("/history/list", h.slaHandler.ListHistory)
	}
	router.GET("/notifications/ws", h.authMiddleware.HandleWebSocket(), h.notificationHandler.WebSocket)
	privateNotifications := router.Group("/notifications")
	privateNotifications.Use(h.authMiddleware.Handle())
	{
		privateNotifications.POST("/list", h.notificationHandler.List)
		privateNotifications.POST("/read", h.notificationHandler.MarkRead)
		privateNotifications.POST("/read-all", h.notificationHandler.MarkAllRead)
		privateNotifications.POST("/preferences/get", h.notificationHandler.GetPreferences)
		privateNotifications.POST("/preferences/update", h.notificationHandler.UpdatePreferences)
		privateNotifications.POST("/devices/register", h.notificationHandler.RegisterDevice)
		privateNotifications.POST("/devices/delete", h.notificationHandler.DeleteDevice)
		privateNotifications.POST("/templates/upsert", h.notificationHandler.UpsertTemplate)
		privateNotifications.POST("/templates/list", h.notificationHandler.ListTemplates)
		privateNotifications.POST("/deliveries/list", h.notificationHandler.ListDeliveries)
	}
	privateAudit := router.Group("/audit")
	privateAudit.Use(h.authMiddleware.Handle())
	{
		privateAudit.POST("/get", h.auditHandler.Get)
		privateAudit.POST("/list", h.auditHandler.List)
	}
	privateAnalytics := router.Group("/analytics")
	privateAnalytics.Use(h.authMiddleware.Handle())
	{
		privateAnalytics.POST("/tickets/overview", h.analyticsHandler.Overview)
		privateAnalytics.POST("/sla/summary", h.analyticsHandler.SLA)
		privateAnalytics.POST("/tickets/breakdown", h.analyticsHandler.Breakdown)
		privateAnalytics.POST("/tickets/daily", h.analyticsHandler.Daily)
		privateAnalytics.POST("/assets/summary", h.analyticsHandler.Assets)
	}
	privateReports := router.Group("/reports")
	privateReports.Use(h.authMiddleware.Handle())
	{
		privateReports.POST("/create", h.reportHandler.Create)
		privateReports.POST("/completion/create", h.reportHandler.CreateCompletion)
		privateReports.POST("/get", h.reportHandler.Get)
		privateReports.POST("/list", h.reportHandler.List)
		privateReports.POST("/cancel", h.reportHandler.Cancel)
		privateReports.POST("/retry", h.reportHandler.Retry)
		privateReports.POST("/download-url", h.reportHandler.Download)
	}
	privateAssets := router.Group("/assets")
	privateAssets.Use(h.authMiddleware.Handle())
	{
		privateAssets.POST("/create", h.assetHandler.Create)
		privateAssets.POST("/get", h.assetHandler.Get)
		privateAssets.POST("/update", h.assetHandler.Update)
		privateAssets.POST("/list", h.assetHandler.List)
		privateAssets.POST("/status", h.assetHandler.ChangeStatus)
		privateAssets.POST("/nearby", h.assetHandler.Nearby)
		privateAssets.POST("/incidents", h.assetHandler.Incident)
		privateAssets.POST("/repairs", h.assetHandler.Repair)
		privateAssets.POST("/inspections", h.assetHandler.Inspection)
		privateAssets.POST("/prediction", h.assetHandler.Prediction)
		privateAssets.POST("/maintenance/create", h.assetHandler.CreatePlan)
		privateAssets.POST("/maintenance/due", h.assetHandler.DuePlans)
		privateAssets.POST("/risks/recalculate", h.assetHandler.Recalculate)
	}

	privateCategories := router.Group("/ticket-categories")
	privateCategories.Use(h.authMiddleware.Handle())
	{
		privateCategories.POST("/create", h.ticketHandler.CreateCategory)
		privateCategories.POST("/get", h.ticketHandler.GetCategory)
		privateCategories.POST("/list", h.ticketHandler.ListCategories)
		privateCategories.POST("/update", h.ticketHandler.UpdateCategory)
		privateCategories.POST("/delete", h.ticketHandler.DeleteCategory)
	}

	privateDepartments := router.Group("/departments")
	privateDepartments.Use(h.authMiddleware.Handle())
	{
		privateDepartments.POST("/create", h.departmentHandler.CreateDepartment)
		privateDepartments.POST("/get", h.departmentHandler.GetDepartmentByID)
		privateDepartments.POST("/list", h.departmentHandler.ListDepartments)
		privateDepartments.POST("/update", h.departmentHandler.UpdateDepartment)
		privateDepartments.POST("/delete", h.departmentHandler.DeleteDepartment)
	}

	privateBrigades := router.Group("/brigades")
	privateBrigades.Use(h.authMiddleware.Handle())
	{
		privateBrigades.POST("/create", h.brigadeHandler.CreateBrigade)
		privateBrigades.POST("/get", h.brigadeHandler.GetBrigadeByID)
		privateBrigades.POST("/list", h.brigadeHandler.ListBrigades)
		privateBrigades.POST("/update", h.brigadeHandler.UpdateBrigade)
		privateBrigades.POST("/deactivate", h.brigadeHandler.DeactivateBrigade)
		privateBrigades.POST("/archive", h.brigadeHandler.ArchiveBrigade)
		privateBrigades.POST("/set-status", h.brigadeHandler.SetBrigadeStatus)
		privateBrigades.POST("/status-history", h.brigadeHandler.GetBrigadeStatusHistory)
		privateBrigades.POST("/get-by-user", h.brigadeHandler.GetBrigadeByUserID)
		privateBrigades.POST("/available", h.brigadeHandler.GetAvailableBrigades)
		privateBrigades.POST("/can-handle-ticket", h.brigadeHandler.CheckBrigadeCanHandleTicket)
	}

	privateBrigadeMembers := router.Group("/brigade-members")
	privateBrigadeMembers.Use(h.authMiddleware.Handle())
	{
		privateBrigadeMembers.POST("/add", h.brigadeHandler.AddBrigadeMember)
		privateBrigadeMembers.POST("/remove", h.brigadeHandler.RemoveBrigadeMember)
		privateBrigadeMembers.POST("/change-role", h.brigadeHandler.ChangeBrigadeMemberRole)
		privateBrigadeMembers.POST("/set-availability", h.brigadeHandler.SetBrigadeMemberAvailability)
		privateBrigadeMembers.POST("/list", h.brigadeHandler.ListBrigadeMembers)
		privateBrigadeMembers.POST("/history", h.brigadeHandler.GetBrigadeMemberHistory)
		privateBrigadeMembers.POST("/status-history", h.brigadeHandler.GetBrigadeMemberStatusHistory)
	}

	privateSkills := router.Group("/skills")
	privateSkills.Use(h.authMiddleware.Handle())
	{
		privateSkills.POST("/create", h.brigadeHandler.CreateSkill)
		privateSkills.POST("/update", h.brigadeHandler.UpdateSkill)
		privateSkills.POST("/deactivate", h.brigadeHandler.DeactivateSkill)
		privateSkills.POST("/list", h.brigadeHandler.ListSkills)
	}

	privateBrigadeSkills := router.Group("/brigade-skills")
	privateBrigadeSkills.Use(h.authMiddleware.Handle())
	{
		privateBrigadeSkills.POST("/add", h.brigadeHandler.AddBrigadeSkill)
		privateBrigadeSkills.POST("/remove", h.brigadeHandler.RemoveBrigadeSkill)
		privateBrigadeSkills.POST("/list", h.brigadeHandler.ListBrigadeSkills)
	}

	privateBrigadeSchedules := router.Group("/brigade-schedules")
	privateBrigadeSchedules.Use(h.authMiddleware.Handle())
	{
		privateBrigadeSchedules.POST("/set", h.brigadeHandler.SetBrigadeSchedule)
		privateBrigadeSchedules.POST("/list", h.brigadeHandler.ListBrigadeSchedule)
	}

	privateBrigadeZones := router.Group("/brigade-zones")
	privateBrigadeZones.Use(h.authMiddleware.Handle())
	{
		privateBrigadeZones.POST("/create", h.brigadeHandler.CreateBrigadeZone)
		privateBrigadeZones.POST("/update", h.brigadeHandler.UpdateBrigadeZone)
		privateBrigadeZones.POST("/delete", h.brigadeHandler.DeleteBrigadeZone)
		privateBrigadeZones.POST("/list", h.brigadeHandler.ListBrigadeZones)
		privateBrigadeZones.POST("/covers-point", h.brigadeHandler.CheckBrigadeCoversPoint)
		privateBrigadeZones.POST("/find-by-point", h.brigadeHandler.FindBrigadesByPoint)
	}

	privateLocations := router.Group("/locations")
	privateLocations.Use(h.authMiddleware.Handle())
	{
		privateLocations.POST("/record", h.locationHandler.RecordPosition)
		privateLocations.POST("/current", h.locationHandler.GetCurrentLocation)
		privateLocations.POST("/current-batch", h.locationHandler.GetCurrentLocations)
		privateLocations.POST("/history", h.locationHandler.ListPositionHistory)
		privateLocations.POST("/nearby", h.locationHandler.FindNearbyBrigades)
	}

	privateGeoZones := router.Group("/geo-zones")
	privateGeoZones.Use(h.authMiddleware.Handle())
	{
		privateGeoZones.POST("/create", h.locationHandler.CreateGeoZone)
		privateGeoZones.POST("/update", h.locationHandler.UpdateGeoZone)
		privateGeoZones.POST("/delete", h.locationHandler.DeleteGeoZone)
		privateGeoZones.POST("/list", h.locationHandler.ListGeoZones)
		privateGeoZones.POST("/check-point", h.locationHandler.CheckPointInZones)
	}

	privateRoutes := router.Group("/routing")
	privateRoutes.Use(h.authMiddleware.Handle())
	{
		privateRoutes.POST("/build", h.routingHandler.BuildRoute)
		privateRoutes.POST("/matrix", h.routingHandler.BuildMatrix)
		privateRoutes.POST("/rank-candidates", h.routingHandler.RankCandidates)
		privateRoutes.POST("/create", h.routingHandler.CreateRoute)
		privateRoutes.POST("/get", h.routingHandler.GetRoute)
		privateRoutes.POST("/recalculate", h.routingHandler.RecalculateRoute)
		privateRoutes.POST("/set-status", h.routingHandler.SetRouteStatus)
		privateRoutes.POST("/list", h.routingHandler.ListRoutes)
	}

	privateDispatch := router.Group("/dispatch")
	privateDispatch.Use(h.authMiddleware.Handle())
	{
		privateDispatch.POST("/preview", h.dispatchHandler.Preview)
		privateDispatch.POST("/reserve", h.dispatchHandler.Reserve)
		privateDispatch.POST("/confirm", h.dispatchHandler.Confirm)
		privateDispatch.POST("/auto", h.dispatchHandler.Auto)
		privateDispatch.POST("/get", h.dispatchHandler.Get)
		privateDispatch.POST("/list", h.dispatchHandler.List)
		privateDispatch.POST("/cancel", h.dispatchHandler.Cancel)
	}

	privateUserProfiles := router.Group("/user-profiles")
	privateUserProfiles.Use(h.authMiddleware.Handle())
	{
		privateUserProfiles.POST("/create", h.profileHandler.CreateUserProfile)
		privateUserProfiles.POST("/get", h.profileHandler.GetUserProfileByID)
		privateUserProfiles.POST("/get-by-user", h.profileHandler.GetUserProfileByUserID)
		privateUserProfiles.GET("/me", h.profileHandler.GetMyUserProfile)
		privateUserProfiles.POST("/list", h.profileHandler.ListUserProfiles)
		privateUserProfiles.POST("/update", h.profileHandler.UpdateUserProfile)
	}

	privateWorkProfiles := router.Group("/work-profiles")
	privateWorkProfiles.Use(h.authMiddleware.Handle())
	{
		privateWorkProfiles.POST("/create", h.profileHandler.CreateWorkProfile)
		privateWorkProfiles.POST("/get", h.profileHandler.GetWorkProfileByID)
		privateWorkProfiles.POST("/get-by-user", h.profileHandler.GetWorkProfileByUserID)
		privateWorkProfiles.POST("/list", h.profileHandler.ListWorkProfiles)
		privateWorkProfiles.POST("/update", h.profileHandler.UpdateWorkProfile)
		privateWorkProfiles.POST("/deactivate", h.profileHandler.DeactivateWorkProfile)
		privateWorkProfiles.POST("/change-department", h.profileHandler.ChangeWorkProfileDepartment)
		privateWorkProfiles.POST("/set-status", h.profileHandler.SetWorkProfileStatus)
		privateWorkProfiles.POST("/status-history", h.profileHandler.GetWorkProfileStatusHistory)
	}

	privateProfileChecks := router.Group("/profile-checks")
	privateProfileChecks.Use(h.authMiddleware.Handle())
	{
		privateProfileChecks.POST("/resolve-working-department", h.profileHandler.ResolveWorkingDepartment)
		privateProfileChecks.POST("/can-join-brigade", h.profileHandler.CheckProfileCanJoinBrigade)
	}

	privateCertificationTypes := router.Group("/certification-types")
	privateCertificationTypes.Use(h.authMiddleware.Handle())
	{
		privateCertificationTypes.POST("/create", h.profileHandler.CreateCertificationType)
		privateCertificationTypes.POST("/update", h.profileHandler.UpdateCertificationType)
		privateCertificationTypes.POST("/list", h.profileHandler.ListCertificationTypes)
	}

	privateCertificationTypeSkills := router.Group("/certification-type-skills")
	privateCertificationTypeSkills.Use(h.authMiddleware.Handle())
	{
		privateCertificationTypeSkills.POST("/add", h.profileHandler.AddCertificationTypeSkill)
		privateCertificationTypeSkills.POST("/remove", h.profileHandler.RemoveCertificationTypeSkill)
		privateCertificationTypeSkills.POST("/list", h.profileHandler.ListCertificationTypeSkills)
	}

	privateWorkProfileCertifications := router.Group("/work-profile-certifications")
	privateWorkProfileCertifications.Use(h.authMiddleware.Handle())
	{
		privateWorkProfileCertifications.POST("/upload", h.profileHandler.UploadWorkProfileCertification)
		privateWorkProfileCertifications.POST("/verify", h.profileHandler.VerifyWorkProfileCertification)
		privateWorkProfileCertifications.POST("/reject", h.profileHandler.RejectWorkProfileCertification)
		privateWorkProfileCertifications.POST("/revoke", h.profileHandler.RevokeWorkProfileCertification)
		privateWorkProfileCertifications.POST("/expire", h.profileHandler.ExpireWorkProfileCertifications)
		privateWorkProfileCertifications.POST("/list", h.profileHandler.ListWorkProfileCertifications)
	}

	privateWorkProfileSkills := router.Group("/work-profile-skills")
	privateWorkProfileSkills.Use(h.authMiddleware.Handle())
	{
		privateWorkProfileSkills.POST("/grant-manual", h.profileHandler.GrantManualWorkProfileSkill)
		privateWorkProfileSkills.POST("/revoke", h.profileHandler.RevokeWorkProfileSkillGrant)
		privateWorkProfileSkills.POST("/list-effective", h.profileHandler.ListEffectiveWorkProfileSkills)
		privateWorkProfileSkills.POST("/batch-list-effective", h.profileHandler.BatchListEffectiveWorkProfileSkills)
		privateWorkProfileSkills.POST("/has-skills", h.profileHandler.CheckWorkProfileHasSkills)
	}

	return router
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
