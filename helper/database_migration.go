package helper

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/ariefsn/gembok/logger"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mongodb"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func MongoMigrateClient(address string) (*migrate.Migrate, error) {
	// Create connection to database
	params := url.Values{}
	params.Add("x-migrations-collection", "migrations")
	params.Add("authSource", "admin")

	uri := address + fmt.Sprintf("?%s", params.Encode())

	m, err := migrate.New(
		"file://migrations/mongo",
		uri,
	)

	if err != nil {
		return nil, errors.New("Init database failed. Error: " + err.Error())
	}

	return m, nil
}

func MongoMigrateUp(address string) error {
	// Create connection to database
	m, err := MongoMigrateClient(address)
	if err != nil {
		return err
	}

	// Migrate up to the latest active version
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		logger.Fatal(fmt.Errorf("unable to migrate up to the latest database schema - %v", err))
	}

	return nil
}

func MongoMigrateDown(address string) error {
	// Create connection to database
	m, err := MongoMigrateClient(address)
	if err != nil {
		return err
	}

	// Migrate down to the latest active version
	if err := m.Down(); err != nil && err != migrate.ErrNoChange {
		logger.Fatal(fmt.Errorf("unable to migrate down - %v", err))
	}

	return nil
}

func MongoMigrateStep(address string, stepNumber int) error {
	// Create connection to database
	m, err := MongoMigrateClient(address)
	if err != nil {
		return err
	}

	// Migrate step to the latest active version
	if err := m.Steps(stepNumber); err != nil && err != migrate.ErrNoChange {
		logger.Fatal(fmt.Errorf("unable to migrate step - %v", err))
	}

	return nil
}

func MongoMigrateForce(address string, version int) error {
	// Create connection to database
	m, err := MongoMigrateClient(address)
	if err != nil {
		return err
	}

	// Migrate force to clean the dirty by force to the latest active version
	if err := m.Force(version); err != nil && err != migrate.ErrNoChange {
		logger.Fatal(fmt.Errorf("unable to migrate force - %v", err))
	}

	return nil
}
