package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	authDlv "github.com/ariefsn/gembok/apps/auth/delivery"
	authSvc "github.com/ariefsn/gembok/apps/auth/service"
	rootDlv "github.com/ariefsn/gembok/apps/root/delivery"
	userRepo "github.com/ariefsn/gembok/apps/user/repository"
	"github.com/ariefsn/gembok/constant"
	. "github.com/ariefsn/gembok/docs"
	"github.com/ariefsn/gembok/env"
	"github.com/ariefsn/gembok/graph"
	"github.com/ariefsn/gembok/graph/resolvers"
	"github.com/ariefsn/gembok/helper"
	"github.com/ariefsn/gembok/logger"
	"github.com/ariefsn/gembok/middlewares"
	"github.com/ariefsn/gembok/models"
	"github.com/ariefsn/gembok/notification"
	"github.com/ariefsn/gembok/validator"
	"github.com/chi-middleware/proxy"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/gorilla/websocket"
	httpSwagger "github.com/swaggo/http-swagger"
)

func init() {
	env.InitEnv()
	logger.InitLogger()
	validator.InitValidator()
}

// @title Auth Service
// @version 3.0
// @description API Auth Service.
// @contact.name API Support
// @contact.url https://ariefsn.dev
// @contact.email hello@ariefsn.dev
// @BasePath /
// @securityDefinitions.apikey	Bearer
// @in							header
// @name						Authorization
// @description				Description for what is this security definition being used
func main() {
	env := env.GetEnv()
	notif := notification.NewNotification()

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Header().Set("content-type", "application/json")
		helper.ResponseJson(w, models.ResponseModel{
			Success: false,
			Code:    constant.ResponseStatusFail.String(),
			Message: "route not found",
		})
	})

	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(405)
		w.Header().Set("content-type", "application/json")
		helper.ResponseJson(w, models.ResponseModel{
			Success: false,
			Code:    constant.ResponseStatusFail.String(),
			Message: "method not allowed",
		})
	})

	corsOpt := cors.Options{
		AllowedOrigins: []string{
			"https://*",
			"http://*",
			"http://localhost:5173",
			"http://localhost:3000",
			env.Urls.Studio,
		},
		AllowOriginFunc: func(r *http.Request, origin string) bool {
			return true
		},
		AllowedHeaders: []string{
			"Authorization",
			"Content-Type",
			"Accept",
			"Origin",
			"User-Agent",
			"Referrer",
			"Host",
			"X-Requested-With",
			"X-CSRF-Token",
			string(constant.HeaderAuthorization),
		},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		ExposedHeaders:   []string{"Content-Length", "Link"},
		Debug:            false,
	}

	corsCfg := cors.New(corsOpt)

	// Setup db
	dbEnv := env.Mongo
	dbAddress := fmt.Sprintf("mongodb://%s:%s@%s:%s", dbEnv.User, dbEnv.Password, dbEnv.Host, dbEnv.Port)
	client, _ := helper.MongoClient(dbAddress)
	db := client.Database(dbEnv.Db)
	rdb := helper.RedisClient(env.Redis)

	// Migration
	addressForMigration := dbAddress + "/" + dbEnv.Db
	// Uncomment this to force, clean dirty and remigrate
	// helper.MongoMigrateForce(addressForMigration, 1)
	err := helper.MongoMigrateUp(addressForMigration)
	if err != nil {
		logger.Error(fmt.Errorf("migrating failed. Error: %s", err.Error()))
	}

	r.Use(proxy.ForwardedHeaders())
	r.Use(middlewares.Inject(*env))
	r.Use(corsCfg.Handler)

	// Repository
	userRepository := userRepo.NewRepository(db, rdb)

	// Service
	authService := authSvc.NewService(userRepository, notif)

	// GraphQL Resolvers Config
	gqlConfig := graph.Config{
		Resolvers: &resolvers.Resolver{
			AuthService: authService,
		},
	}

	srv := handler.NewDefaultServer(graph.NewExecutableSchema(gqlConfig))
	srv.AroundOperations(func(ctx context.Context, next graphql.OperationHandler) graphql.ResponseHandler {
		oc := graphql.GetOperationContext(ctx)

		logger.Info(fmt.Sprintf("[%s]", strings.ToUpper(string(oc.Operation.Operation))), models.M{
			"operationName": oc.OperationName,
			"variables":     oc.Variables,
		})

		return next(ctx)
	})
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})
	srv.AddTransport(transport.MultipartForm{
		MaxUploadSize: 10 * 1024 * 1024,
	})
	srv.AddTransport(transport.Websocket{
		KeepAlivePingInterval: 10 * time.Second,
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		InitFunc: func(ctx context.Context, initPayload transport.InitPayload) (context.Context, *transport.InitPayload, error) {
			fmt.Println(initPayload)
			return ctx, &initPayload, nil
			// return webSocketInit(ctx, initPayload)
		},
	})
	srv.Use(extension.Introspection{})

	r.Handle("/graphui", playground.Handler("GraphQL playground", "/graphql"))
	r.Handle("/graphql", srv)

	// Handlers
	r.Mount("/", rootDlv.NewHandlers())
	r.Route("/api/v1", func(r chi.Router) {
		// Register Handlers Here
		r.Mount("/auth", authDlv.NewHandler(authService))
	})

	// Swagger Docs
	origin := fmt.Sprintf("http://%s:%s", env.App.Host, env.App.Port)
	if env.Urls.Origin != "" {
		origin = env.Urls.Origin
	}

	originSplit := strings.Split(origin, "//")

	SwaggerInfo.Host = originSplit[1] + "/api/v1"
	r.Get("/docs/*", httpSwagger.Handler(
		httpSwagger.URL(env.Urls.Origin+"/docs/doc.json"),
	))

	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		route = strings.Replace(route, "/*/", "/", -1)
		fmt.Printf("%s %s\n", method, route)
		return nil
	}

	if err := chi.Walk(r, walkFunc); err != nil {
		fmt.Printf("Logging err: %s\n", err.Error())
	}

	host := env.App.Host
	port := env.App.Port

	log.Printf("connect to http://%s:%s/ for GraphQL playground", host, port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
