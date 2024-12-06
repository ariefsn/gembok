package delivery

import (
	"encoding/json"
	"net/http"

	"github.com/ariefsn/gembok/constant"
	"github.com/ariefsn/gembok/helper"
	"github.com/ariefsn/gembok/middlewares"
	"github.com/ariefsn/gembok/models"
	"github.com/go-chi/chi/v5"
)

type Handler struct {
	authService models.AuthService
}

func NewHandler(authService models.AuthService) *chi.Mux {
	r := chi.NewRouter()
	h := &Handler{
		authService: authService,
	}

	r.Post("/signin", h.SignIn)
	r.Post("/signup", h.SignUp)
	r.Post("/forgot-password", h.ForgotPassword)
	r.Patch("/reset-password", h.ResetPassword)
	r.Patch("/verify", h.Verify)

	// Authenticated
	r.Group(func(r chi.Router) {
		r.Use(middlewares.Jwt(authService))

		r.Get("/profile", h.Profile)
		r.Delete("/profile", h.ProfileDelete)
		r.Patch("/change-password", h.ChangePassword)
		r.Get("/signout", h.SignOut)
	})

	return r
}

// @Tags Auth
// @Summary Sign in with credentials or oauth
// @Description Provider can be one of credentials, github. The email/username and password field are required if the provider is credentials.
// @Accept json
// @Produce json
// @Param request body models.AuthSignInPayload true "Payload"
// @Success 200 {object} swagger.AuthSignInResponse
// @Router /auth/signin [post]
func (h *Handler) SignIn(w http.ResponseWriter, r *http.Request) {
	var dto models.AuthSignInPayload

	err := json.NewDecoder(r.Body).Decode(&dto)
	if err != nil {
		helper.ResponseJsonError(w, constant.ResponseStatusInvalidPayload, constant.ResponseStatusInvalidPayload.String(), http.StatusBadRequest)
		return
	}

	res, code, err := h.authService.SignIn(r.Context(), dto)
	if err != nil {
		helper.ResponseJsonError(w, code, err.Error(), http.StatusUnauthorized)
		return
	}

	helper.ResponseJsonSuccess(w, code, res)
}

// @Tags Auth
// @Summary Sign up with credentials
// @Description Sign up with credentials, email and password
// @Accept json
// @Produce json
// @Param request body models.AuthSignUpPayload true "Payload"
// @Success 200 {object} swagger.AuthSignUpResponse
// @Router /auth/signup [post]
func (h *Handler) SignUp(w http.ResponseWriter, r *http.Request) {
	var dto models.AuthSignUpPayload

	err := json.NewDecoder(r.Body).Decode(&dto)
	if err != nil {
		helper.ResponseJsonError(w, constant.ResponseStatusInvalidPayload, constant.ResponseStatusInvalidPayload.String(), http.StatusBadRequest)
		return
	}

	res, code, err := h.authService.SignUp(r.Context(), dto)
	if err != nil {
		helper.ResponseJsonError(w, code, err.Error(), http.StatusInternalServerError)
		return
	}

	helper.ResponseJsonSuccess(w, code, res.Id)
}

// @Tags Auth
// @Summary Get profile for authenticated user
// @Description Get profile for authenticated user
// @Accept json
// @Produce json
// @Security 	Bearer
// @Success 200 {object} swagger.AuthProfileResponse
// @Router /auth/profile [get]
func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	res, code, err := h.authService.Profile(r.Context())
	if err != nil {
		helper.ResponseJsonError(w, code, err.Error(), http.StatusInternalServerError)
		return
	}

	helper.ResponseJsonSuccess(w, code, res)
}

// @Tags Auth
// @Summary Logout for authenticated user, and blacklist the token
// @Description Logout for authenticated user, and blacklist the token
// @Accept json
// @Produce json
// @Security 	Bearer
// @Success 200 {object} swagger.AuthSignOutResponse
// @Router /auth/signout [get]
func (h *Handler) SignOut(w http.ResponseWriter, r *http.Request) {
	code, err := h.authService.SignOut(r.Context())
	if err != nil {
		helper.ResponseJsonError(w, code, err.Error(), http.StatusInternalServerError)
		return
	}

	helper.ResponseJsonSuccess(w, code, constant.ResponseStatusSuccess.String())
}

// @Tags Auth
// @Summary Forgot Password
// @Description Forgot password, will send the link via an email
// @Accept json
// @Produce json
// @Param request body models.AuthForgotPasswordPayload true "Payload"
// @Success 200 {object} swagger.AuthForgotPasswordResponse
// @Router /auth/forgot-password [post]
func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var dto models.AuthForgotPasswordPayload

	err := json.NewDecoder(r.Body).Decode(&dto)
	if err != nil {
		helper.ResponseJsonError(w, constant.ResponseStatusInvalidPayload, constant.ResponseStatusInvalidPayload.String(), http.StatusBadRequest)
		return
	}

	code, err := h.authService.ForgotPassword(r.Context(), dto)
	if err != nil {
		helper.ResponseJsonError(w, code, err.Error(), http.StatusInternalServerError)
		return
	}

	helper.ResponseJsonSuccess(w, code, code.String())
}

// @Tags Auth
// @Summary Reset Password
// @Description Reset the password, needs the reset token
// @Accept json
// @Produce json
// @Param request body models.AuthResetPasswordPayload true "Payload"
// @Success 200 {object} swagger.AuthResetPasswordResponse
// @Router /auth/reset-password [patch]
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var dto models.AuthResetPasswordPayload

	err := json.NewDecoder(r.Body).Decode(&dto)
	if err != nil {
		helper.ResponseJsonError(w, constant.ResponseStatusInvalidPayload, constant.ResponseStatusInvalidPayload.String(), http.StatusBadRequest)
		return
	}

	code, err := h.authService.ResetPassword(r.Context(), dto)
	if err != nil {
		helper.ResponseJsonError(w, code, err.Error(), http.StatusInternalServerError)
		return
	}

	helper.ResponseJsonSuccess(w, code, code.String())
}

// @Tags Auth
// @Summary Change password for authenticated user
// @Description Change password for authenticated user
// @Accept json
// @Produce json
// @Security 	Bearer
// @Param request body models.AuthChangePasswordPayload true "Payload"
// @Success 200 {object} swagger.AuthChangePasswordResponse
// @Router /auth/change-password [patch]
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var dto models.AuthChangePasswordPayload

	err := json.NewDecoder(r.Body).Decode(&dto)
	if err != nil {
		helper.ResponseJsonError(w, constant.ResponseStatusInvalidPayload, constant.ResponseStatusInvalidPayload.String(), http.StatusBadRequest)
		return
	}

	code, err := h.authService.ChangePassword(r.Context(), dto)
	if err != nil {
		helper.ResponseJsonError(w, code, err.Error(), http.StatusInternalServerError)
		return
	}

	helper.ResponseJsonSuccess(w, code, code.String())
}

// @Tags Auth
// @Summary Verify
// @Description Verify email or phone
// @Accept json
// @Produce json
// @Param request body models.AuthVerificationPayload true "Payload"
// @Success 200 {object} swagger.AuthVerificationResponse
// @Router /auth/verify [patch]
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	var dto models.AuthVerificationPayload

	err := json.NewDecoder(r.Body).Decode(&dto)
	if err != nil {
		helper.ResponseJsonError(w, constant.ResponseStatusInvalidPayload, constant.ResponseStatusInvalidPayload.String(), http.StatusBadRequest)
		return
	}

	code, err := h.authService.Verify(r.Context(), dto)
	if err != nil {
		helper.ResponseJsonError(w, code, err.Error(), http.StatusInternalServerError)
		return
	}

	helper.ResponseJsonSuccess(w, code, code.String())
}

// @Tags Auth
// @Summary Delete own account
// @Description Delete own account and blacklist the access token
// @Accept json
// @Produce json
// @Security 	Bearer
// @Param request body models.AuthDeletePayload true "Payload"
// @Success 200 {object} swagger.AuthDeleteResponse
// @Router /auth/profile [delete]
func (h *Handler) ProfileDelete(w http.ResponseWriter, r *http.Request) {
	var dto models.AuthDeletePayload

	err := json.NewDecoder(r.Body).Decode(&dto)
	if err != nil {
		helper.ResponseJsonError(w, constant.ResponseStatusInvalidPayload, constant.ResponseStatusInvalidPayload.String(), http.StatusBadRequest)
		return
	}

	code, err := h.authService.Delete(r.Context(), dto)
	if err != nil {
		helper.ResponseJsonError(w, code, err.Error(), http.StatusInternalServerError)
		return
	}

	helper.ResponseJsonSuccess(w, code, code.String())
}
