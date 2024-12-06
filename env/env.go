package env

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ariefsn/gembok/logger"
	"github.com/joho/godotenv"
)

type EnvApp struct {
	Name string
	Host string
	Port string
}

type EnvDb struct {
	Host     string
	Port     string
	User     string
	Password string
	Db       string
	DbIndex  int
}

type EnvUrls struct {
	Studio string
	Origin string
}

type EnvApiKeys struct {
}

type EnvTerkirim struct {
	ApiKey         string
	EmailSender    string
	EmailAlias     string
	WhatsappSender string
}

type Env struct {
	App                     EnvApp
	Debug                   bool
	Mongo                   EnvDb
	Redis                   EnvDb
	Jwt                     EnvJwt
	ApiKeys                 EnvApiKeys
	Urls                    EnvUrls
	Terkirim                EnvTerkirim
	SignInAttemp            int
	SignUpCodeExpiry        int
	SignUpVerificationPath  string
	ResetPasswordCodeExpiry int
	ResetPasswordPath       string
}

type EnvJwt struct {
	Secret string
	Expiry int
}

type envValue struct {
	value    string
	fallback interface{}
}

func (e envValue) String() string {
	if e.value == "" && e.fallback != nil {
		return fmt.Sprintf("%s", e.fallback)
	}
	return e.value
}

func (e envValue) Int() int {
	if e.value == "" && e.fallback != nil {
		return e.fallback.(int)
	}
	v, err := strconv.Atoi(e.value)
	if err != nil {
		logger.Error(err)
	}
	return v
}

func (e envValue) Bool() bool {
	if e.value == "" {
		return false
	}

	v, err := strconv.ParseBool(e.value)
	if err != nil {
		logger.Error(err)
	}
	return v
}

var _env *Env

func fromEnv(key string, fallback ...interface{}) envValue {
	var fb interface{}
	if len(fallback) > 0 {
		fb = fallback[0]
	}
	return envValue{
		value:    os.Getenv(key),
		fallback: fb,
	}
}

func InitEnv(envFile ...string) {
	err := godotenv.Load(envFile...)
	if err != nil {
		logger.Warning(err.Error())
	}
	_env = &Env{
		App: EnvApp{
			Name: fromEnv("APP_NAME", "APP").String(),
			Host: fromEnv("APP_HOST", "0.0.0.0").String(),
			Port: fromEnv("APP_PORT", "6001").String(),
		},
		Debug: fromEnv("Debug", true).Bool(),
		Mongo: EnvDb{
			Host:     fromEnv("MONGO_HOST").String(),
			Port:     fromEnv("MONGO_PORT").String(),
			User:     fromEnv("MONGO_USER").String(),
			Password: fromEnv("MONGO_PASSWORD").String(),
			Db:       fromEnv("MONGO_DB").String(),
		},
		Redis: EnvDb{
			Host:     fromEnv("REDIS_HOST").String(),
			Port:     fromEnv("REDIS_PORT").String(),
			User:     fromEnv("REDIS_USER").String(),
			Password: fromEnv("REDIS_PASSWORD").String(),
			DbIndex:  fromEnv("REDIS_DB").Int(),
		},
		Jwt: EnvJwt{
			Secret: fromEnv("JWT_SECRET").String(),
			Expiry: fromEnv("JWT_EXPIRY", 300).Int(),
		},
		ApiKeys: EnvApiKeys{},
		Terkirim: EnvTerkirim{
			ApiKey:         fromEnv("TERKIRIM_API_KEY").String(),
			EmailSender:    fromEnv("TERKIRIM_EMAIL_SENDER").String(),
			EmailAlias:     fromEnv("TERKIRIM_EMAIL_SENDER_NAME", "Notification").String(),
			WhatsappSender: fromEnv("TERKIRIM_WHATSAPP_SENDER").String(),
		},
		Urls: EnvUrls{
			Studio: fromEnv("URL_STUDIO").String(),
			Origin: fromEnv("URL_ORIGIN").String(),
		},
		SignInAttemp:            fromEnv("SIGNIN_ATTEMP", 0).Int(),
		SignUpCodeExpiry:        fromEnv("SIGNUP_CODE_EXPIRY", 15).Int(),
		SignUpVerificationPath:  fromEnv("SIGNUP_VERIFICATION_PATH").String(),
		ResetPasswordCodeExpiry: fromEnv("RESET_PASSWORD_CODE_EXPIRY", 15).Int(),
		ResetPasswordPath:       fromEnv("RESET_PASSWORD_PATH").String(),
	}
}

func GetEnv() *Env {
	if _env == nil {
		InitEnv()
	}

	return _env
}
