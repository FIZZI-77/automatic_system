package handlers

import authv1 "auth/auth/v1"

type AuthHandler struct {
	authClient authv1.AuthServiceClient
}

func NewAuthHandler(authClient authv1.AuthServiceClient) *AuthHandler {
	return &AuthHandler{authClient: authClient}
}
