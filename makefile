generate.gql:
	go run github.com/99designs/gqlgen generate

migrate.install:
	go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest && go install -tags 'mongodb' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

migrate.create:
	migrate create -ext json -dir ./migrations/mongo -seq ${name}
