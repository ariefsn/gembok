package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ariefsn/gembok/constant"
	"github.com/ariefsn/gembok/env"
	"github.com/ariefsn/gembok/helper"
	"github.com/ariefsn/gembok/models"
	"github.com/ariefsn/gembok/notification"
	"github.com/ariefsn/gembok/validator"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

type authService struct {
	userRepo models.UserRepository
	notif    notification.Notification
}

// Delete implements models.AuthService.
func (a *authService) Delete(ctx context.Context, payload models.AuthDeletePayload) (code constant.ResponseStatus, err error) {
	err = validator.ValidateStruct(payload)
	if err != nil {
		return constant.ResponseStatusInvalidPayload, err
	}

	token := helper.AccessTokenFromContext(ctx)
	claims := helper.JwtClaimsFromContext(ctx)

	exists, _ := a.userRepo.GetByIdentifier(ctx, claims.Id)
	if exists == nil {
		return constant.ResponseStatusDataNotFound, constant.ResponseStatusDataNotFound.Error()
	}

	if bcrypt.CompareHashAndPassword([]byte(exists.Password), []byte(payload.Password)) != nil {
		return constant.ResponseStatusInvalidCredentials, constant.ResponseStatusInvalidCredentials.Error()
	}

	_, err = a.userRepo.Delete(ctx, exists.Id)
	if err != nil {
		return constant.ResponseStatusRepositoryFailed, constant.ResponseStatusRepositoryFailed.Error()
	}

	a.userRepo.BlacklistToken(ctx, token)

	return constant.ResponseStatusSuccess, nil
}

// Verify implements models.AuthService.
func (a *authService) Verify(ctx context.Context, payload models.AuthVerificationPayload) (code constant.ResponseStatus, err error) {
	err = validator.ValidateStruct(payload)
	if err != nil {
		return constant.ResponseStatusInvalidPayload, err
	}

	exists, _ := a.userRepo.GetByIdentifier(ctx, payload.Id)
	if exists == nil {
		return constant.ResponseStatusDataNotFound, constant.ResponseStatusDataNotFound.Error()
	}

	isVerified := exists.IsEmailVerified
	verifyData := exists.EmailVerification
	if payload.Type == constant.VerificationTypePhone {
		isVerified = exists.IsPhoneVerified
		verifyData = exists.PhoneVerification
	}

	if isVerified {
		return constant.ResponseStatusSuccess, nil
	}

	if verifyData == nil {
		return constant.ResponseStatusDataNotFound, constant.ResponseStatusDataNotFound.Error()
	}

	if payload.Code != verifyData.Code {
		return constant.ResponseStatusVerificationFailed, constant.ResponseStatusVerificationFailed.Error()
	}

	_, err = helper.JwtVerify[helper.JwtVerificationClaims](verifyData.Token)
	if err != nil {
		return constant.ResponseStatusAccessTokenExpired, constant.ResponseStatusTokenExpired.Error()
	}

SWITCH_VERIFY:
	switch payload.Type {
	case constant.VerificationTypeEmail:
		exists.IsEmailVerified = true
		exists.EmailVerification = nil
		break SWITCH_VERIFY
	case constant.VerificationTypePhone:
		exists.IsPhoneVerified = true
		exists.PhoneVerification = nil
		break SWITCH_VERIFY
	}

	exists.UpdatedAt = helper.ToPtr(time.Now())
	exists.UpdatedBy = "System"

	_, err = a.userRepo.Update(ctx, exists)
	if err != nil {
		return constant.ResponseStatusRepositoryFailed, err
	}

	return constant.ResponseStatusSuccess, nil
}

// ChangePassword implements models.AuthService.
func (a *authService) ChangePassword(ctx context.Context, payload models.AuthChangePasswordPayload) (code constant.ResponseStatus, err error) {
	err = validator.ValidateStruct(payload)
	if err != nil {
		return constant.ResponseStatusInvalidPayload, err
	}

	claims := helper.JwtClaimsFromContext(ctx)

	exists, _ := a.userRepo.GetByEmail(ctx, claims.Email)
	if exists == nil {
		return constant.ResponseStatusDataNotFound, constant.ResponseStatusDataNotFound.Error()
	}

	if bcrypt.CompareHashAndPassword([]byte(exists.Password), []byte(payload.OldPassword)) != nil {
		return constant.ResponseStatusInvalidCredentials, constant.ResponseStatusInvalidCredentials.Error()
	}

	generatedPassword, _ := bcrypt.GenerateFromPassword([]byte(payload.NewPassword), bcrypt.DefaultCost)
	exists.Password = string(generatedPassword)

	exists.UpdatedAt = helper.ToPtr(time.Now())
	exists.UpdatedBy = claims.Id

	_, err = a.userRepo.Update(ctx, exists)
	if err != nil {
		return constant.ResponseStatusRepositoryFailed, err
	}

	return constant.ResponseStatusSuccess, nil
}

// ResetPassword implements models.AuthService.
func (a *authService) ResetPassword(ctx context.Context, payload models.AuthResetPasswordPayload) (code constant.ResponseStatus, err error) {
	err = validator.ValidateStruct(payload)
	if err != nil {
		return constant.ResponseStatusInvalidPayload, err
	}

	claims, err := helper.JwtVerify[helper.JwtVerificationClaims](payload.Token)
	if err != nil {
		return constant.ResponseStatusInvalidToken, err
	}

	if claims.Type != string(helper.JwtTokenTypeResetPassword) {
		return constant.ResponseStatusInvalidClaims, constant.ResponseStatusInvalidClaims.Error()
	}

	exists, _ := a.userRepo.GetById(ctx, claims.Id)
	if exists == nil {
		return constant.ResponseStatusDataNotFound, constant.ResponseStatusDataNotFound.Error()
	}

	if !exists.IsEmailVerified {
		return constant.ResponseStatusAccountInactive, constant.ResponseStatusAccountInactive.Error()
	}

	generatedPassword, _ := bcrypt.GenerateFromPassword([]byte(payload.NewPassword), bcrypt.DefaultCost)
	exists.Password = string(generatedPassword)

	exists.UpdatedAt = helper.ToPtr(time.Now())
	exists.UpdatedBy = "System"

	_, err = a.userRepo.Update(ctx, exists)
	if err != nil {
		return constant.ResponseStatusRepositoryFailed, err
	}

	go a.sendEmailResetPassword(*exists)

	return constant.ResponseStatusSuccess, nil
}

// ForgotPassword implements models.AuthService.
func (a *authService) ForgotPassword(ctx context.Context, payload models.AuthForgotPasswordPayload) (code constant.ResponseStatus, err error) {
	err = validator.ValidateStruct(payload)
	if err != nil {
		return constant.ResponseStatusInvalidPayload, err
	}

	exists, _ := a.userRepo.GetByEmail(ctx, payload.Email)
	if exists == nil {
		return constant.ResponseStatusDataNotFound, constant.ResponseStatusDataNotFound.Error()
	}

	if !exists.IsEmailVerified {
		return constant.ResponseStatusAccountInactive, constant.ResponseStatusAccountInactive.Error()
	}

	go a.sendEmailForgotPassword(*exists)

	return constant.ResponseStatusSuccess, nil
}

func (a *authService) sendEmailForgotPassword(data models.UserData) error {
	env := env.GetEnv()
	cfg := helper.TemplateConfig()
	subject := cfg.GetString("forgotPassword.subject")
	tmplName := cfg.GetString("forgotPassword.template")
	urlLink := fmt.Sprintf("%s%s", env.Urls.Studio, env.ResetPasswordPath)

	expiryIn := env.ResetPasswordCodeExpiry
	fullName := strings.TrimSpace(strings.Join([]string{data.FirstName, data.LastName}, " "))

	tmpl, err := helper.Template(tmplName)
	if err != nil {
		return err
	}

	tokenClaims := jwt.MapClaims{
		"id":   data.Id,
		"type": helper.JwtTokenTypeResetPassword,
		"exp":  time.Now().Add(time.Minute * time.Duration(expiryIn)).Unix(),
	}

	token, err := helper.JwtGenerate(tokenClaims)
	if err != nil {
		return err
	}

	link, _ := url.Parse(urlLink)
	q := link.Query()
	q.Set("token", token)

	link.RawQuery = q.Encode()

	_, err = a.notif.SendEmail(notification.SendEmailPayload{
		Subject:        subject,
		RecipientEmail: data.Email,
		Body:           tmpl,
		Variables: models.M{
			"fullName":  fullName,
			"token":     token,
			"expiredAt": expiryIn,
			"url":       link.String(),
		},
	})

	return err
}

func (a *authService) sendEmailResetPassword(data models.UserData) error {
	env := env.GetEnv()
	cfg := helper.TemplateConfig()
	subject := cfg.GetString("resetPassword.subject")
	tmplName := cfg.GetString("resetPassword.template")
	urlLink := env.Urls.Studio

	fullName := strings.TrimSpace(strings.Join([]string{data.FirstName, data.LastName}, " "))

	tmpl, err := helper.Template(tmplName)
	if err != nil {
		return err
	}

	link, _ := url.Parse(urlLink)
	q := link.Query()
	link.RawQuery = q.Encode()

	_, err = a.notif.SendEmail(notification.SendEmailPayload{
		Subject:        subject,
		RecipientEmail: data.Email,
		Body:           tmpl,
		Variables: models.M{
			"fullName": fullName,
			"url":      link.String(),
		},
	})

	return err
}

func (a *authService) sendEmailSignUp(data models.UserData) error {
	env := env.GetEnv()
	cfg := helper.TemplateConfig()
	subject := cfg.GetString("signUpVerification.subject")
	tmplName := cfg.GetString("signUpVerification.template")
	expiryIn := env.SignUpCodeExpiry
	email := data.Email
	code := data.EmailVerification.Code
	fullName := strings.TrimSpace(strings.Join([]string{data.FirstName, data.LastName}, " "))

	tmpl, err := helper.Template(tmplName)
	if err != nil {
		return err
	}

	link, _ := url.Parse(fmt.Sprintf("%s%s", env.Urls.Studio, env.SignUpVerificationPath))
	q := link.Query()
	q.Set("type", string(constant.VerificationTypeEmail))
	q.Set("id", email)
	q.Set("code", code)
	link.RawQuery = q.Encode()

	_, err = a.notif.SendEmail(notification.SendEmailPayload{
		Subject:        subject,
		RecipientEmail: email,
		Body:           tmpl,
		Variables: models.M{
			"fullName":  fullName,
			"email":     email,
			"expiredAt": expiryIn,
			"code":      code,
			"url":       link.String(),
		},
	})

	return err
}

func (a *authService) generateVerificationCode(verificationType constant.VerificationType, identifier string, expInMinutes int) (*models.UserDataVerification, error) {
	exp := time.Now().Add(time.Duration(expInMinutes) * time.Minute)
	code := helper.RandomNumericCode(6)

	tokenClaims := jwt.MapClaims{
		"type": verificationType,
		"code": code,
		"id":   identifier,
		"exp":  exp.Unix(),
	}

	token, err := helper.JwtGenerate(tokenClaims)
	if err != nil {
		return nil, err
	}

	return &models.UserDataVerification{
		Code:  code,
		Token: token,
	}, nil
}

// CheckBlacklistToken implements models.AuthService.
func (a *authService) CheckBlacklistToken(ctx context.Context) (code constant.ResponseStatus, err error) {
	token := helper.AccessTokenFromContext(ctx)

	err = a.userRepo.CheckBlacklistToken(ctx, token)
	if err != nil {
		return constant.ResponseStatusAccessTokenBlacklisted, err
	}

	return constant.ResponseStatusSuccess, nil
}

// GenerateAuthTokens implements models.AuthService.
func (a *authService) GenerateAuthTokens(ctx context.Context, provider string, data models.UserDataClaims) (res *models.AuthSignInResponse, code constant.ResponseStatus, err error) {
	err = validator.ValidateStruct(data)
	if err != nil {
		return nil, constant.ResponseStatusInvalidPayload, err
	}

	env := env.GetEnv()

	accessTokenClaims := jwt.MapClaims{
		"id":    data.Id,
		"email": data.Email,
		"type":  helper.JwtTokenTypeAccess,
		"exp":   time.Now().Add(time.Minute * time.Duration(env.Jwt.Expiry)).Unix(),
	}

	refreshTokenClaims := jwt.MapClaims{
		"id":   data.Id,
		"type": helper.JwtTokenTypeRefresh,
		"exp":  time.Now().Add(time.Minute * 2 * time.Duration(env.Jwt.Expiry)).Unix(),
	}

	accessToken, err := helper.JwtGenerate(accessTokenClaims)
	if err != nil {
		return nil, constant.ResponseStatusServiceFailed, err
	}

	refreshToken, err := helper.JwtGenerate(refreshTokenClaims)
	if err != nil {
		return nil, constant.ResponseStatusServiceFailed, err
	}

	return &models.AuthSignInResponse{
		Provider:     provider,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, constant.ResponseStatusSuccess, nil
}

// MagicLink implements models.AuthService.
func (a *authService) MagicLink(ctx context.Context, payload models.AuthMagicLinkPayload) (res *models.AuthSignInResponse, code constant.ResponseStatus, err error) {
	panic("unimplemented")
}

// Profile implements models.AuthService.
func (a *authService) Profile(ctx context.Context) (res *models.UserDataView, code constant.ResponseStatus, err error) {
	claims := helper.JwtClaimsFromContext(ctx)

	exists, err := a.userRepo.GetById(ctx, claims.Id)
	if err != nil {
		return nil, constant.ResponseStatusDataNotFound, err
	}

	res = new(models.UserDataView).FromData(exists)

	return res, constant.ResponseStatusSuccess, nil
}

// Refresh implements models.AuthService.
func (a *authService) Refresh(ctx context.Context, payload models.AuthRefreshTokenPayload) (res *models.AuthSignInResponse, code constant.ResponseStatus, err error) {
	err = validator.ValidateStruct(payload)
	if err != nil {
		return nil, constant.ResponseStatusInvalidPayload, err
	}

	claims, err := helper.JwtVerify[helper.JwtClaims](payload.RefreshToken)
	if err != nil {
		return nil, constant.ResponseStatusInvalidRefreshToken, err
	}

	id := claims.Id
	provider := claims.Provider

	exists, err := a.userRepo.GetById(ctx, id)
	if err != nil {
		return nil, constant.ResponseStatusDataNotFound, err
	}

	return a.GenerateAuthTokens(ctx, provider, models.UserDataClaims{
		Id:    exists.Id,
		Email: exists.Email,
	})
}

// SignIn implements models.AuthService.
func (a *authService) SignIn(ctx context.Context, payload models.AuthSignInPayload) (res *models.AuthSignInResponse, code constant.ResponseStatus, err error) {
	err = validator.ValidateStruct(payload)
	if err != nil {
		return nil, constant.ResponseStatusInvalidPayload, err
	}

	if payload.IsProviderOauth() {
		return &models.AuthSignInResponse{
			Provider: string(payload.Provider),
			AuthUrl:  "https://github.com/login/oauth/authorize?client_id=Ov23liKivBlgwnnWuRtg",
		}, constant.ResponseStatusSuccess, nil
	}

	if err := validator.ValidateVar(payload.Email, "required"); err != nil {
		return nil, constant.ResponseStatusInvalidPayload, err
	}

	if err := validator.ValidateVar(payload.Password, "required,password"); err != nil {
		return nil, constant.ResponseStatusInvalidPayload, err
	}

	exists, _ := a.userRepo.GetByEmail(ctx, payload.Email)
	if exists == nil {
		return nil, constant.ResponseStatusDataNotFound, errors.New("account not found")
	}

	// check is verified
	if !exists.IsEmailVerified {
		return nil, constant.ResponseStatusAccountInactive, constant.ResponseStatusAccountInactive.Error()
	}

	// check ban
	if exists.IsBanned {
		return nil, constant.ResponseStatusAccountBanned, errors.New(exists.BanReason)
	}

	if bcrypt.CompareHashAndPassword([]byte(exists.Password), []byte(payload.Password)) != nil {
		env := env.GetEnv()
		maxAttemp := env.SignInAttemp
		if maxAttemp > 0 {
			exists.SignInAttemp++
			if exists.SignInAttemp == maxAttemp {
				exists.IsBanned = true
				exists.BanReason = "account banned due to suspicious login attempts"
			}

			exists.UpdatedAt = helper.ToPtr(time.Now())
			exists.UpdatedBy = "System"

			a.userRepo.Update(ctx, exists)
		}

		return nil, constant.ResponseStatusInvalidCredentials, constant.ResponseStatusInvalidCredentials.Error()
	}

	return a.GenerateAuthTokens(ctx, "credentials", models.UserDataClaims{
		Id:    exists.Id,
		Email: exists.Email,
	})
}

// SignInProvider implements models.AuthService.
func (a *authService) SignInProvider(ctx context.Context, payload models.AuthProviderPayload) (res *models.AuthSignInResponse, code constant.ResponseStatus, err error) {
	panic("unimplemented")
}

// SignOut implements models.AuthService.
func (a *authService) SignOut(ctx context.Context) (code constant.ResponseStatus, err error) {
	token := helper.AccessTokenFromContext(ctx)

	err = a.userRepo.BlacklistToken(ctx, token)
	if err != nil {
		return constant.ResponseStatusInvalidAccessToken, err
	}

	return constant.ResponseStatusSuccess, nil
}

// SignUp implements models.AuthService.
func (a *authService) SignUp(ctx context.Context, payload models.AuthSignUpPayload) (res *models.UserDataView, code constant.ResponseStatus, err error) {
	err = validator.ValidateStruct(payload)
	if err != nil {
		return nil, constant.ResponseStatusInvalidPayload, err
	}

	generatedPassword, _ := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	newUser := &models.UserData{
		Id:        primitive.NewObjectID().Hex(),
		FirstName: payload.FirstName,
		LastName:  payload.LastName,
		Email:     payload.Email,
		Password:  string(generatedPassword),
		Audit: &models.Audit{
			CreatedAt: time.Now(),
			CreatedBy: "System",
		},
	}

	exists, _ := a.userRepo.GetByEmail(ctx, payload.Email)
	env := env.GetEnv()
	codeExpiryIn := env.SignUpCodeExpiry
	if exists != nil {
		if exists.IsEmailVerified {
			return nil, constant.ResponseStatusEmailRegistered, constant.ResponseStatusEmailRegistered.Error()
		}

		// If not verified, resend the code
		exists.EmailVerification, _ = a.generateVerificationCode(constant.VerificationTypeEmail, exists.Email, codeExpiryIn)

		exists.UpdatedAt = helper.ToPtr(time.Now())
		exists.UpdatedBy = "System"

		updated, _ := a.userRepo.Update(ctx, exists)

		go a.sendEmailSignUp(*updated)

		return new(models.UserDataView).FromData(exists), constant.ResponseStatusSuccess, nil
	}

	generatedPassword, _ = bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	newUser.EmailVerification, _ = a.generateVerificationCode(constant.VerificationTypeEmail, newUser.Email, codeExpiryIn)
	newUser.Password = string(generatedPassword)

	created, err := a.userRepo.Create(ctx, newUser)
	if err != nil {
		return nil, constant.ResponseStatusRepositoryFailed, err
	}

	res = new(models.UserDataView).FromData(created)

	go a.sendEmailSignUp(*created)

	return res, constant.ResponseStatusSuccess, nil
}

func NewService(userRepo models.UserRepository, notif notification.Notification) models.AuthService {
	return &authService{
		userRepo: userRepo,
		notif:    notif,
	}
}
