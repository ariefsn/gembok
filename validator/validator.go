package validator

import (
	"fmt"

	"github.com/ariefsn/gembok/models"
	val "github.com/go-playground/validator/v10"
)

var validate *val.Validate

func InitValidator() {
	validate = val.New(val.WithRequiredStructEnabled())
	validate.RegisterValidation("password", ValidatePassword)
}

func Validator() *val.Validate {
	return validate
}

func MapValidatorMessages(v val.FieldError) error {
	switch v.Tag() {
	case "required":
		return fmt.Errorf("%s field is required", v.Field())
	case "email":
		return fmt.Errorf("%s field is not valid email format", v.Field())
	case "len":
		return fmt.Errorf("%s field length should be %s", v.Field(), v.Param())
	case "min":
		return fmt.Errorf("%s field length minimum %s", v.Field(), v.Param())
	}

	return v
}

func ValidateStruct(s interface{}) error {
	errors := validate.Struct(s)

	if errors != nil {
		validationErrors := errors.(val.ValidationErrors)
		for _, v := range validationErrors {
			return MapValidatorMessages(v)
		}
	}

	return nil
}

func ValidateVar(field interface{}, tag string) error {
	errors := validate.Var(field, tag)

	if errors != nil {
		validationErrors := errors.(val.ValidationErrors)
		for _, v := range validationErrors {
			return v
		}
	}

	return nil
}

func ValidateVarMap(data, rules models.M) models.M {
	return validate.ValidateMap(data, rules)
}

func ParseValidationError(err error) val.ValidationErrors {
	if err != nil {
		parsed := err.(val.ValidationErrors)
		return parsed
	}

	return nil
}
