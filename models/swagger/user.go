package swagger

import "github.com/ariefsn/gembok/models"

type AuthSignInResponse struct {
	Success bool                       `json:"success"`
	Code    string                     `json:"code"`
	Message string                     `json:"message"`
	Data    *models.AuthSignInResponse `json:"data"`
}

type AuthSignUpResponse struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type AuthProfileResponse struct {
	Success bool                 `json:"success"`
	Code    string               `json:"code"`
	Message string               `json:"message"`
	Data    *models.UserDataView `json:"data"`
}

type AuthSignOutResponse struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type AuthForgotPasswordResponse struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type AuthResetPasswordResponse struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type AuthChangePasswordResponse struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type AuthVerificationResponse struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type AuthDeleteResponse struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}
