package constant

import "errors"

type ResponseStatus string

const (
	ResponseStatusSuccess                ResponseStatus = "000"
	ResponseStatusFail                   ResponseStatus = "001"
	ResponseStatusInvalidPayload         ResponseStatus = "003"
	ResponseStatusServiceFailed          ResponseStatus = "004"
	ResponseStatusInvalidAccessToken     ResponseStatus = "005"
	ResponseStatusInvalidRefreshToken    ResponseStatus = "006"
	ResponseStatusInvalidClaims          ResponseStatus = "007"
	ResponseStatusRequiredAccessToken    ResponseStatus = "008"
	ResponseStatusAccessTokenBlacklisted ResponseStatus = "009"
	ResponseStatusAccessTokenExpired     ResponseStatus = "010"
	ResponseStatusVerificationFailed     ResponseStatus = "011"
	ResponseStatusVerificationExpired    ResponseStatus = "012"
	ResponseStatusVerificationSuccess    ResponseStatus = "013"
	ResponseStatusEmailRegistered        ResponseStatus = "014"
	ResponseStatusRepositoryFailed       ResponseStatus = "015"
	ResponseStatusInvalidCredentials     ResponseStatus = "016"
	ResponseStatusDataNotFound           ResponseStatus = "017"
	ResponseStatusAccountBanned          ResponseStatus = "018"
	ResponseStatusInvalidToken           ResponseStatus = "019"
	ResponseStatusTokenExpired           ResponseStatus = "020"
	ResponseStatusAccountInactive        ResponseStatus = "021"
	ResponseStatusInvalidCode            ResponseStatus = "022"
	ResponseStatusCodeExpired            ResponseStatus = "023"
)

func (r ResponseStatus) String() string {
	return map[ResponseStatus]string{
		ResponseStatusSuccess:                "success",
		ResponseStatusFail:                   "failed",
		ResponseStatusInvalidPayload:         "invalid payload",
		ResponseStatusServiceFailed:          "service failed",
		ResponseStatusInvalidAccessToken:     "invalid access token",
		ResponseStatusInvalidRefreshToken:    "invalid refresh token",
		ResponseStatusInvalidClaims:          "invalid claims",
		ResponseStatusRequiredAccessToken:    "access token is required",
		ResponseStatusAccessTokenBlacklisted: "access token is blacklisted",
		ResponseStatusAccessTokenExpired:     "access token is expired",
		ResponseStatusVerificationFailed:     "verification failed",
		ResponseStatusVerificationExpired:    "verification code is expired",
		ResponseStatusVerificationSuccess:    "verification success",
		ResponseStatusEmailRegistered:        "email registered",
		ResponseStatusRepositoryFailed:       "repository failed",
		ResponseStatusInvalidCredentials:     "invalid credentials",
		ResponseStatusDataNotFound:           "data not found",
		ResponseStatusAccountBanned:          "account is banned",
		ResponseStatusInvalidToken:           "invalid token",
		ResponseStatusTokenExpired:           "token is expired",
		ResponseStatusAccountInactive:        "account is not active",
		ResponseStatusInvalidCode:            "invalid code",
		ResponseStatusCodeExpired:            "code is expired",
	}[r]
}

func (r ResponseStatus) Error() error {
	return errors.New(r.String())
}
