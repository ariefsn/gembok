package repository

import (
	"context"
	"errors"
	"time"

	"github.com/ariefsn/gembok/env"
	"github.com/ariefsn/gembok/models"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type userRepository struct {
	Db  *mongo.Database
	Rdb *redis.Client
	env *env.Env
}

// BlacklistToken implements models.UserRepository.
func (u *userRepository) BlacklistToken(ctx context.Context, token string) error {
	exp := time.Second * 3 * time.Duration(u.env.Jwt.Expiry)

	return u.Rdb.Set(ctx, token, "blacklisted", exp).Err()
}

// CheckBlacklistToken implements models.UserRepository.
func (u *userRepository) CheckBlacklistToken(ctx context.Context, token string) error {
	val, _ := u.Rdb.Get(ctx, token).Result()
	if val != "" {
		return errors.New("token blacklisted")
	}
	return nil
}

// Create implements models.UserRepository.
func (u *userRepository) Create(ctx context.Context, data *models.UserData) (*models.UserData, error) {
	_, err := u.Db.Collection(data.TableName()).InsertOne(ctx, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Delete implements models.UserRepository.
func (u *userRepository) Delete(ctx context.Context, id string) (*models.UserData, error) {
	exists, err := u.GetById(ctx, id)
	if err != nil {
		return nil, err
	}

	_, err = u.Db.Collection(exists.TableName()).DeleteOne(ctx, models.M{"_id": id})
	if err != nil {
		return nil, err
	}

	return exists, nil
}

// Update implements models.UserRepository.
func (u *userRepository) Update(ctx context.Context, data *models.UserData) (*models.UserData, error) {
	exists, err := u.GetById(ctx, data.Id)
	if err != nil {
		return nil, err
	}

	upsert := true
	returnDoc := options.After

	res := u.Db.Collection(data.TableName()).FindOneAndUpdate(ctx, models.M{"_id": exists.Id}, models.M{
		"$set": data,
	}, &options.FindOneAndUpdateOptions{
		ReturnDocument: &returnDoc,
		Upsert:         &upsert,
	})

	if res.Err() != nil {
		return nil, res.Err()
	}

	return data, nil
}

// GetByEmail implements models.UserRepository.
func (u *userRepository) GetByEmail(ctx context.Context, email string) (*models.UserData, error) {
	filters := models.M{
		"email": email,
	}

	res := new(models.UserData)

	err := u.Db.Collection(res.TableName()).FindOne(ctx, filters).Decode(&res)

	if err != nil {
		return nil, err
	}

	return res, nil
}

// GetById implements models.UserRepository.
func (u *userRepository) GetById(ctx context.Context, id string) (*models.UserData, error) {
	filters := models.M{
		"_id": id,
	}

	res := new(models.UserData)

	err := u.Db.Collection(res.TableName()).FindOne(ctx, filters).Decode(&res)

	if err != nil {
		return nil, err
	}

	return res, nil
}

// GetByUsername implements models.UserRepository.
func (u *userRepository) GetByUsername(ctx context.Context, username string) (*models.UserData, error) {
	filters := models.M{
		"username": username,
	}

	res := new(models.UserData)

	err := u.Db.Collection(res.TableName()).FindOne(ctx, filters).Decode(&res)

	if err != nil {
		return nil, err
	}

	return res, nil
}

// GetByIdentifier implements models.UserRepository.
func (u *userRepository) GetByIdentifier(ctx context.Context, identifier string) (*models.UserData, error) {
	filters := models.M{
		"$or": []models.M{
			{
				"email": identifier,
			},
			{
				"username": identifier,
			},
			{
				"_id": identifier,
			},
		},
	}

	res := new(models.UserData)

	err := u.Db.Collection(res.TableName()).FindOne(ctx, filters).Decode(&res)

	if err != nil {
		return nil, err
	}

	return res, nil
}

func NewRepository(db *mongo.Database, rdb *redis.Client) models.UserRepository {
	return &userRepository{
		Db:  db,
		Rdb: rdb,
		env: env.GetEnv(),
	}
}
