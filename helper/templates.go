package helper

import (
	"os"
	"path"

	"github.com/spf13/viper"
)

var viperTemplate *viper.Viper

func Template(templateTitle string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	tmpPath := path.Join(wd, "templates", templateTitle)
	b, err := os.ReadFile(tmpPath)

	if err != nil {
		return "", err
	}

	return string(b), nil
}

func TemplateConfig() *viper.Viper {
	if viperTemplate == nil {
		wd, _ := os.Getwd()
		viperTemplate = viper.New()
		viperTemplate.SetConfigType("json")
		viperTemplate.AddConfigPath(path.Join(wd, "templates"))
		viperTemplate.SetConfigName("config")
	}

	viperTemplate.ReadInConfig()

	return viperTemplate
}
