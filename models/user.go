package models

import (
	"context"
	"strings"
	"time"

	"github.com/ariefsn/gembok/constant"
)

type AuthSignInPayload struct {
	Provider constant.AuthProvider `json:"provider"`
	Email    string                `json:"email"`
	Password string                `json:"password"`
}

func (a *AuthSignInPayload) IsProviderCredentials() bool {
	p := strings.ToLower(string(a.Provider))
	return p == "" || !constant.AuthProviderOauth[constant.AuthProvider(p)]
}

func (a *AuthSignInPayload) IsProviderOauth() bool {
	return !a.IsProviderCredentials()
}

type AuthSignUpPayload struct {
	FirstName string `json:"firstName" validate:"required"`
	LastName  string `json:"lastName" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" bson:"password" validate:"alphanum|containsany=@ # $ % ^ & . ? / = - _,min=8"`
}

type AuthProviderPayload struct {
	Provider string `json:"provider"`
}

type AuthMagicLinkPayload struct {
	Email string `json:"email"`
}

type AuthRefreshTokenPayload struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

type AuthVerificationPayload struct {
	Type constant.VerificationType `json:"type" validate:"required,oneof=email phone"`
	Id   string                    `json:"id" validate:"required"`
	Code string                    `json:"code" validate:"required"`
}

type AuthDeletePayload struct {
	Password string `json:"password" validate:"required"`
}

type AuthSignInResponse struct {
	Provider     string `json:"provider"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	AuthUrl      string `json:"authUrl"`
}

type UserDataClaims struct {
	Id    string `json:"id"`
	Email string `json:"email"`
}

type UserDataVerification struct {
	Code  string `json:"code" bson:"code" validate:"numeric,len=6"`
	Token string `json:"token" bson:"token"`
}

type UserData struct {
	// Providers               []*UserProviderData `json:"providers" bson:"providers"`
	Id                string                `json:"id" bson:"_id" validate:"alphanum"`
	FirstName         string                `json:"firstName" bson:"firstName" validate:"required,alpha"`
	LastName          string                `json:"lastName" bson:"lastName" validate:"alpha"`
	Email             string                `json:"email" bson:"email" validate:"required,email"`
	Username          string                `json:"username" bson:"username" validate:"alphanum"`
	Phone             string                `json:"phone" bson:"phone" validate:"num"`
	Password          string                `json:"password" bson:"password" validate:"alphanum|containsany=@ # $ % ^ & . ? / = - _,min=8"`
	Image             string                `json:"image" bson:"image" validate:"url"`
	IsEmailVerified   bool                  `json:"isEmailVerified" bson:"isEmailVerified" validate:"boolean"`
	IsPhoneVerified   bool                  `json:"isPhoneVerified" bson:"isPhoneVerified" validate:"boolean"`
	EmailVerification *UserDataVerification `json:"emailVerification" validate:"dive"`
	PhoneVerification *UserDataVerification `json:"phoneVerification" validate:"dive"`
	SignInAttemp      int                   `json:"signInAttemp" bson:"signInAttemp"`
	IsBanned          bool                  `json:"isBanned" bson:"isBanned" validate:"boolean"`
	BanReason         string                `json:"banReason" bson:"banReason"`
	BanExpiredAt      *time.Time            `json:"banExpiredAt" bson:"banExpiredAt"`
	*Audit            `bson:",inline"`
	// Role                    string     `json:"role" bson:"role" validate:"required,oneof=admin user"`
}

func (u *UserData) TableName() string {
	return "users"
}

type UserDataView struct {
	Id              string     `json:"id" bson:"_id" validate:"alphanum"`
	FirstName       string     `json:"firstName" bson:"firstName" validate:"required alpha"`
	LastName        string     `json:"lastName" bson:"lastName" validate:"alpha"`
	Email           string     `json:"email" bson:"email" validate:"required email"`
	Username        string     `json:"username" bson:"username" validate:"alphanum"`
	Phone           string     `json:"phone" bson:"phone" validate:"num"`
	Image           string     `json:"image" bson:"image" validate:"url"`
	IsEmailVerified bool       `json:"isEmailVerified" bson:"isEmailVerified" validate:"boolean"`
	IsPhoneVerified bool       `json:"isPhoneVerified" bson:"isPhoneVerified" validate:"boolean"`
	IsBanned        bool       `json:"isBanned" bson:"isBanned" validate:"boolean"`
	BanReason       string     `json:"banReason" bson:"banReason"`
	BanExpiredAt    *time.Time `json:"banExpiredAt" bson:"banExpiredAt"`
	*Audit          `bson:",inline"`
}

func (u *UserDataView) FromData(data *UserData) *UserDataView {
	return &UserDataView{
		Id:              data.Id,
		FirstName:       data.FirstName,
		LastName:        data.LastName,
		Email:           data.Email,
		Username:        data.Username,
		Phone:           data.Phone,
		Image:           data.Image,
		IsEmailVerified: data.IsEmailVerified,
		IsPhoneVerified: data.IsPhoneVerified,
		IsBanned:        data.IsBanned,
		BanReason:       data.BanReason,
		BanExpiredAt:    data.BanExpiredAt,
		Audit:           data.Audit,
	}
}

type AuthProfileUpdatePayload struct {
	FirstName string `json:"firstName" bson:"firstName" validate:"required,alpha"`
	LastName  string `json:"lastName" bson:"lastName" validate:"alpha"`
	Email     string `json:"email" bson:"email" validate:"required email"`
	Username  string `json:"username" bson:"username" validate:"alphanum"`
	Phone     string `json:"phone" bson:"phone" validate:"num"`
}

type UserDataUpdatePayload struct {
	FirstName string `json:"firstName" bson:"firstName" validate:"required,alpha"`
	LastName  string `json:"lastName" bson:"lastName" validate:"alpha"`
	IsBanned  bool   `json:"isBanned" bson:"isBanned" validate:"boolean"`
}

type AuthForgotPasswordPayload struct {
	Email string `json:"email" validate:"required,email"`
}

type AuthResetPasswordPayload struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required,password"`
}

type AuthChangePasswordPayload struct {
	OldPassword string `json:"oldPassword" validate:"password"`
	NewPassword string `json:"newPassword" validate:"required,password"`
}

type AuthService interface {
	SignIn(ctx context.Context, payload AuthSignInPayload) (res *AuthSignInResponse, code constant.ResponseStatus, err error)
	SignUp(ctx context.Context, payload AuthSignUpPayload) (res *UserDataView, code constant.ResponseStatus, err error)
	SignInProvider(ctx context.Context, payload AuthProviderPayload) (res *AuthSignInResponse, code constant.ResponseStatus, err error)
	Profile(ctx context.Context) (res *UserDataView, code constant.ResponseStatus, err error)
	Refresh(ctx context.Context, payload AuthRefreshTokenPayload) (res *AuthSignInResponse, code constant.ResponseStatus, err error)
	MagicLink(ctx context.Context, payload AuthMagicLinkPayload) (res *AuthSignInResponse, code constant.ResponseStatus, err error)
	SignOut(ctx context.Context) (code constant.ResponseStatus, err error)
	// GenerateTokens(ctx context.Context, provider string, data UserDataClaims) (res *AuthSignInResponse, code constant.ResponseStatus, err error)
	CheckBlacklistToken(ctx context.Context) (code constant.ResponseStatus, err error)
	ForgotPassword(ctx context.Context, payload AuthForgotPasswordPayload) (code constant.ResponseStatus, err error)
	ResetPassword(ctx context.Context, payload AuthResetPasswordPayload) (code constant.ResponseStatus, err error)
	ChangePassword(ctx context.Context, payload AuthChangePasswordPayload) (code constant.ResponseStatus, err error)
	Verify(ctx context.Context, payload AuthVerificationPayload) (code constant.ResponseStatus, err error)
	Delete(ctx context.Context, payload AuthDeletePayload) (code constant.ResponseStatus, err error)
}

type UserRepository interface {
	GetByEmail(ctx context.Context, email string) (*UserData, error)
	GetById(ctx context.Context, id string) (*UserData, error)
	GetByUsername(ctx context.Context, username string) (*UserData, error)
	GetByIdentifier(ctx context.Context, identifier string) (*UserData, error)
	Create(ctx context.Context, data *UserData) (*UserData, error)
	Update(ctx context.Context, data *UserData) (*UserData, error)
	Delete(ctx context.Context, id string) (*UserData, error)
	BlacklistToken(ctx context.Context, token string) error
	CheckBlacklistToken(ctx context.Context, token string) error
}
