package handlers

import (
	"gateway/src/core/middleware"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
)

func handleGRPCError(c *gin.Context, err error) {
	st, ok := status.FromError(err)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	switch st.Code() {
	case codes.InvalidArgument:
		c.JSON(http.StatusBadRequest, gin.H{"error": st.Message()})
	case codes.Unauthenticated:
		c.JSON(http.StatusUnauthorized, gin.H{"error": st.Message()})
	case codes.PermissionDenied:
		c.JSON(http.StatusForbidden, gin.H{"error": st.Message()})
	case codes.NotFound:
		c.JSON(http.StatusNotFound, gin.H{"error": st.Message()})
	case codes.AlreadyExists:
		c.JSON(http.StatusConflict, gin.H{"error": st.Message()})
	case codes.Aborted:
		c.JSON(http.StatusConflict, gin.H{"error": st.Message()})
	case codes.DeadlineExceeded:
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": "upstream service timeout"})
	case codes.Unavailable:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upstream service unavailable"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}

type Handler struct {
	authHandler       *AuthHandler
	ticketHandler     *TicketHandler
	departmentHandler *DepartmentHandler
	brigadeHandler    *BrigadeHandler
	authMiddleware    *middleware.AuthMiddleware
}

func NewHandler(authHandler *AuthHandler, ticketHandler *TicketHandler, departmentHandler *DepartmentHandler, brigadeHandler *BrigadeHandler, authMiddleware *middleware.AuthMiddleware) *Handler {
	return &Handler{
		authHandler:       authHandler,
		ticketHandler:     ticketHandler,
		departmentHandler: departmentHandler,
		brigadeHandler:    brigadeHandler,
		authMiddleware:    authMiddleware,
	}
}

func (h *Handler) InitRouters() *gin.Engine {

	router := gin.New()

	router.Use(middleware.RequestID())
	router.Use(middleware.IdempotencyKey())
	router.Use(middleware.RateLimit(middleware.RateLimitConfig{
		Name:   "global",
		Limit:  300,
		Burst:  100,
		Window: time.Minute,
		SkipFunc: func(c *gin.Context) bool {
			return c.Request.URL.Path == "/health"
		},
	}))
	router.Use(middleware.RequestLogger())
	router.Use(gin.Recovery())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	publicAuth := router.Group("/auth")
	publicAuth.Use(middleware.RateLimit(middleware.RateLimitConfig{
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
	privateAuth.Use(middleware.RateLimit(middleware.RateLimitConfig{
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
		privateTickets.POST("/change-status", h.ticketHandler.ChangeTicketStatus)
		privateTickets.POST("/assign-brigade", h.ticketHandler.AssignBrigade)
		privateTickets.POST("/cancel", h.ticketHandler.CancelTicket)
		privateTickets.POST("/complete", h.ticketHandler.CompleteTicket)
		privateTickets.POST("/status-history", h.ticketHandler.GetTicketStatusHistory)
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

	return router
}
