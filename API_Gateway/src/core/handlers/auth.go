package handlers

import (
	authv1 "auth/auth/v1"
	"context"
	"gateway/models"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

type AuthHandler struct {
	authClient authv1.AuthServiceClient
}

func NewAuthHandler(authClient authv1.AuthServiceClient) *AuthHandler {
	return &AuthHandler{authClient: authClient}
}

func (ah *AuthHandler) Login(c *gin.Context) {

	var req models.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := ah.authClient.Login(ctx, &authv1.LoginRequest{
		Email:     req.Email,
		Password:  req.Password,
		ClientId:  req.ClientID,
		Ip:        c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
	})
	if err != nil {
		handleGRPCError(c, err)
		return
	}

	result := &models.LoginResponse{
		AccessToken:          res.AccessToken,
		RefreshToken:         res.RefreshToken,
		AccessExpiresAtUnix:  res.AccessExpiresAtUnix,
		RefreshExpiresAtUnix: res.RefreshExpiresAtUnix,
		SessionID:            res.SessionId,
		TokenType:            res.TokenType,
	}

	c.JSON(http.StatusOK, result)
}

func (ah *AuthHandler) Logout(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := ah.authClient.Logout(ctx, &authv1.LogoutRequest{
		UserId:    c.GetString("user_id"),
		SessionId: c.GetString("session_id"),
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	result := &models.LogoutResponse{
		Success: res.Success,
	}

	c.JSON(http.StatusOK, result)
}

func (ah *AuthHandler) LogoutAll(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := ah.authClient.LogoutAll(ctx, &authv1.LogoutAllRequest{
		UserId: c.GetString("user_id"),
	})
	if err != nil {
		handleGRPCError(c, err)
		return
	}
	result := &models.LogoutAllResponse{
		Success:      res.Success,
		RevokedCount: res.RevokedCount,
	}

	c.JSON(http.StatusOK, result)
}

func (ah *AuthHandler) Register(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req models.RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	res, err := ah.authClient.Register(ctx, &authv1.RegisterRequest{
		Email:    req.Email,
		Password: req.Password,
		Username: req.Username,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	result := &models.RegisterResponse{
		UserID:        res.UserId,
		Email:         res.Email,
		EmailVerified: res.EmailVerified,
	}

	c.JSON(http.StatusCreated, result)
}

func (ah *AuthHandler) Refresh(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req models.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: err.Error(),
		})
		return
	}
	res, err := ah.authClient.Refresh(ctx, &authv1.RefreshRequest{
		RefreshToken: req.RefreshToken,
		ClientId:     req.ClientID,
		Ip:           c.ClientIP(),
		UserAgent:    c.GetHeader("User-Agent"),
	})
	if err != nil {
		handleGRPCError(c, err)
		return
	}

	result := &models.RefreshResponse{
		RefreshToken:         res.RefreshToken,
		AccessToken:          res.AccessToken,
		AccessExpiresAtUnix:  res.AccessExpiresAtUnix,
		RefreshExpiresAtUnix: res.RefreshExpiresAtUnix,
		SessionID:            res.SessionId,
		TokenType:            res.TokenType,
	}

	c.JSON(http.StatusOK, result)
}

func (ah *AuthHandler) GetUserAuthInfo(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := ah.authClient.GetUserAuthInfo(ctx, &authv1.GetUserAuthInfoRequest{
		UserId: c.GetString("user_id"),
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	result := &models.MeResponse{
		UserID:        res.UserId,
		Email:         res.Email,
		Roles:         res.Roles,
		Permissions:   res.Permissions,
		IsActive:      res.IsActive,
		EmailVerified: res.EmailVerified,
	}

	c.JSON(http.StatusOK, result)
}

func (ah *AuthHandler) GetJWKS(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := ah.authClient.GetJWKS(ctx, &authv1.GetJWKSRequest{})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.Data(
		http.StatusOK,
		"application/json; charset=utf-8",
		[]byte(res.JwksJson),
	)
}

func (ah *AuthHandler) ChangePassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	res, err := ah.authClient.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		UserId:              c.GetString("user_id"),
		OldPassword:         req.OldPassword,
		NewPassword:         req.NewPassword,
		SessionId:           c.GetString("session_id"),
		RevokeOtherSessions: req.RevokeOtherSessions,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	result := &models.ChangePasswordResponse{
		Success:                  res.Success,
		InvalidatedSessionsCount: res.InvalidatedSessionsCount,
	}

	c.JSON(http.StatusOK, result)
}

func (ah *AuthHandler) SendVerificationEmail(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{Error: "unauthorized"})
		return
	}

	var req models.SendVerificationEmailRequest

	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
			return
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := ah.authClient.SendVerificationEmail(ctx, &authv1.SendVerificationEmailRequest{
		UserId: userID,
		Email:  req.Email,
	})
	if err != nil {
		handleGRPCError(c, err)
		return
	}

	c.JSON(http.StatusOK, models.SendVerificationEmailResponse{
		Success:       res.Success,
		ExpiresAtUnix: res.ExpiresAtUnix,
	})
}

func (ah *AuthHandler) VerifyEmail(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req models.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	res, err := ah.authClient.VerifyEmail(ctx, &authv1.VerifyEmailRequest{
		Token: req.Token,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	result := &models.VerifyEmailResponse{
		Success:       res.Success,
		UserID:        res.UserId,
		Email:         res.Email,
		EmailVerified: res.EmailVerified,
		Message:       res.Message,
	}

	c.JSON(http.StatusOK, result)
}

func (ah *AuthHandler) RequestPasswordReset(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req models.RequestPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	res, err := ah.authClient.RequestPasswordReset(ctx, &authv1.RequestPasswordResetRequest{
		Email: req.Email,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	result := &models.RequestPasswordResetResponse{
		Success:       res.Success,
		ExpiresAtUnix: res.ExpiresAtUnix,
	}

	c.JSON(http.StatusOK, result)
}

func (ah *AuthHandler) ResetPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	res, err := ah.authClient.ResetPassword(ctx, &authv1.ResetPasswordRequest{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	})

	if err != nil {
		handleGRPCError(c, err)
		return
	}

	result := &models.ResetPasswordResponse{
		Success:                  res.Success,
		InvalidatedSessionsCount: res.InvalidatedSessionsCount,
	}

	c.JSON(http.StatusOK, result)
}
