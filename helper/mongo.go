package helper

import (
	"errors"
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type FilterOperator string

const (
	FoContains  FilterOperator = "$contains"
	FoStartWith FilterOperator = "$startWith"
	FoEndWith   FilterOperator = "$endWith"
	FoEq        FilterOperator = "$eq"
	FoNe        FilterOperator = "$ne"
	FoIn        FilterOperator = "$in"
	FoNin       FilterOperator = "$nin"
	FoGt        FilterOperator = "$gt"
	FoGte       FilterOperator = "$gte"
	FoLt        FilterOperator = "$lt"
	FoLte       FilterOperator = "$lte"
	FoAll       FilterOperator = "$all"
)

type MongoSortBy string

const (
	SortByAsc  MongoSortBy = "ASC"
	SortByDesc MongoSortBy = "DESC"
)

type MongoSort struct {
	SortField string
	SortBy    MongoSortBy
}

type MongoAggregate struct {
	Skip  *int64
	Limit *int64
	Sort  []MongoSort
	Match bson.M
}

func NewMongoAggregate() *MongoAggregate {
	a := new(MongoAggregate)

	return a
}

func (a *MongoAggregate) BuildPipe() []bson.M {
	pipe := []bson.M{}

	// build match
	if a.Match != nil && len(a.Match) > 0 {
		pipe = append(pipe, MongoMatch(a.Match))
	}

	// build sort
	if len(a.Sort) > 0 {
		pipe = append(pipe, bson.M{"$sort": MongoSorting(a.Sort...)})
	}

	// build skip
	if a.Skip != nil && *a.Skip > -1 {
		pipe = append(pipe, MongoSkip(*a.Skip))
	}

	// build limit
	if a.Limit != nil && *a.Limit > -1 {
		if *a.Skip < 0 {
			pipe = append(pipe, MongoLimit(*a.Limit))
		} else {
			pipe = append(pipe, MongoLimit(*a.Limit))
		}
	}

	return pipe
}

func MongoPipe(aggregate MongoAggregate) []bson.M {
	return aggregate.BuildPipe()
}

func MongoMatch(filter bson.M) bson.M {
	return bson.M{
		"$match": filter,
	}
}

func MongoSorting(sort ...MongoSort) bson.M {
	s := bson.M{}

	for _, v := range sort {
		sortBy := 1

		if v.SortBy == SortByDesc {
			sortBy = -1
		}

		s[v.SortField] = sortBy
	}

	return s
}

func MongoSkip(skip int64) bson.M {
	return bson.M{"$skip": skip}
}

func MongoLimit(limit int64) bson.M {
	return bson.M{"$limit": limit}
}

func MongoFilter(operator FilterOperator, field string, value interface{}) bson.M {
	switch operator {
	case FoEq, FoNe, FoIn, FoNin, FoGt, FoGte, FoLt, FoLte, FoAll:
		return bson.M{
			field: bson.M{
				string(operator): value,
			},
		}
	case FoContains, FoStartWith, FoEndWith:
		var regexPattern string
		regexOpt := "i"

		switch operator {
		case FoContains:
			regexPattern = fmt.Sprintf(".*%s.*", value)
		case FoStartWith:
			regexPattern = fmt.Sprintf("^%s", value)
		case FoEndWith:
			regexPattern = fmt.Sprintf("%s$", value)
		}

		return bson.M{
			field: primitive.Regex{
				Pattern: regexPattern,
				Options: regexOpt,
			},
		}
	default:
		return nil
	}
}

func BuildMongoOrders(orders string, separators ...string) []MongoSort {
	ordersSlice := []MongoSort{}

	separatorOrder := ","
	separatorOrderBy := "*"

	for k, v := range separators {
		switch k {
		case 0:
			separatorOrder = v
		case 1:
			separatorOrderBy = v
		}
	}

	orderSplit := strings.Split(orders, separatorOrder)

	if orders == "" || len(orderSplit) == 0 {
		return ordersSlice
	}

	for _, os := range orderSplit {
		sortSplit := strings.Split(os, separatorOrderBy)

		sortBy := SortByAsc

		if len(sortSplit) == 2 {

			if sortSplit[1] == "-1" || strings.ToLower(sortSplit[1]) == "desc" {
				sortBy = SortByDesc
			}

			ordersSlice = append(ordersSlice, MongoSort{
				SortField: sortSplit[0],
				SortBy:    sortBy,
			})
		}
	}

	return ordersSlice
}

type MongoLookupOptions struct {
	From         string
	LocalField   string
	ForeignField string
	As           string
}

func MongoLookup(opt MongoLookupOptions) bson.M {
	return bson.M{
		"$lookup": bson.M{
			"from":         opt.From,
			"localField":   opt.LocalField,
			"foreignField": opt.ForeignField,
			"as":           opt.As,
		},
	}
}

type MongoUnwindOptions struct {
	Path              string
	IncludeArrayIndex string
	PreserveEmpty     bool
}

func MongoUnwind(opt MongoUnwindOptions) bson.M {
	return bson.M{
		"$unwind": bson.M{
			"path":                       opt.Path,
			"preserveNullAndEmptyArrays": opt.PreserveEmpty,
			// "includeArrayIndex": opt.IncludeArrayIndex,
		},
	}
}

func MongoIn(field string, inValues interface{}) bson.M {
	return bson.M{
		field: bson.M{
			"$in": inValues,
		},
	}
}

func MongoSet(data bson.M) bson.M {
	return bson.M{
		"$set": data,
	}
}

func MongoUnionWith(collection string, pipelines []bson.M) bson.M {
	return bson.M{
		"$unionWith": bson.M{
			"coll":     collection,
			"pipeline": pipelines,
		},
	}
}

type MongoGraphLookupOptions struct {
	From             string
	StartWith        string
	ConnectFromField string
	ConnectToField   string
	DepthField       string
	As               string
}

func MongoGraphLookup(opt MongoGraphLookupOptions) bson.M {
	return bson.M{
		"$graphLookup": bson.M{
			"from":             opt.From,
			"startWith":        opt.StartWith,
			"connectFromField": opt.ConnectFromField,
			"connectToField":   opt.ConnectToField,
			"depthField":       opt.DepthField,
			"as":               opt.As,
		},
	}
}

func MongoDateToString(field, format string) bson.M {
	return bson.M{
		"$dateToString": bson.M{
			"date":   field,
			"format": format,
		},
	}
}

func ParseMongoError(err error) error {
	if err == nil {
		return nil
	}

	if strings.Contains(err.Error(), "no documents in result") {
		return errors.New("no document found")
	}

	return err
}
