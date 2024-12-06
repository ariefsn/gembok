package helper

import (
	"net/http"

	"github.com/ariefsn/gembok/constant"
	"github.com/ariefsn/gembok/models"
)

func ResponseJson(w http.ResponseWriter, data models.ResponseModel, statusCode ...int) {
	_statusCode := http.StatusOK

	if len(statusCode) > 0 {
		_statusCode = statusCode[0]
	}

	w.WriteHeader(_statusCode)

	w.Write(ToBytes(data))
}

func ResponseJsonSuccess(w http.ResponseWriter, code constant.ResponseStatus, data interface{}, statusCode ...int) {
	ResponseJson(w, models.ResponseModel{
		Success: true,
		Code:    string(code),
		Data:    data,
	}, statusCode...)
}

func ResponseJsonError(w http.ResponseWriter, code constant.ResponseStatus, message string, statusCode ...int) {
	ResponseJson(w, models.ResponseModel{
		Success: false,
		Code:    string(code),
		Message: message,
	}, statusCode...)
}
