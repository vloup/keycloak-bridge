package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	common "github.com/cloudtrust/common-healthcheck"
	"github.com/cloudtrust/go-jobs"
	"github.com/cloudtrust/go-jobs/job"
	job_lock "github.com/cloudtrust/go-jobs/lock"
	job_status "github.com/cloudtrust/go-jobs/status"
	fb_flaki "github.com/cloudtrust/keycloak-bridge/api/flaki/fb"
	"github.com/cloudtrust/keycloak-bridge/api/user/fb"
	"github.com/cloudtrust/keycloak-bridge/internal/elasticsearch"
	"github.com/cloudtrust/keycloak-bridge/internal/idgenerator"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/redis"
	"github.com/cloudtrust/keycloak-bridge/pkg/event"
	"github.com/cloudtrust/keycloak-bridge/pkg/export"
	"github.com/cloudtrust/keycloak-bridge/pkg/health"
	health_job "github.com/cloudtrust/keycloak-bridge/pkg/job"
	"github.com/cloudtrust/keycloak-bridge/pkg/middleware"
	"github.com/cloudtrust/keycloak-bridge/pkg/user"
	keycloak "github.com/cloudtrust/keycloak-client"
	sentry "github.com/getsentry/raven-go"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	gokit_influx "github.com/go-kit/kit/metrics/influx"
	"github.com/go-kit/kit/ratelimit"
	grpc_transport "github.com/go-kit/kit/transport/grpc"
	"github.com/google/flatbuffers/go"
	"github.com/gorilla/mux"
	influx "github.com/influxdata/influxdb/client/v2"
	_ "github.com/lib/pq"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	jaeger "github.com/uber/jaeger-client-go/config"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
)

var (
	// ComponentName is the name of the component.
	ComponentName = "keycloak-bridge"
	// ComponentID is an unique ID generated by Flaki at component startup.
	ComponentID = "unknown"
	// Version of the component.
	Version = "1.1"
	// Environment is filled by the compiler.
	Environment = "unknown"
	// GitCommit is filled by the compiler.
	GitCommit = "unknown"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	// Logger.
	var logger = log.NewJSONLogger(os.Stdout)
	{
		logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
	}
	defer logger.Log("msg", "goodbye")

	// Configurations.
	var c = config(log.With(logger, "unit", "config"))
	var (
		// Component
		grpcAddr = c.GetString("component-grpc-host-port")
		httpAddr = c.GetString("component-http-host-port")

		// Flaki
		flakiAddr = c.GetString("flaki-host-port")

		// Keycloak
		keycloakConfig = keycloak.Config{
			Addr:     fmt.Sprintf("http://%s", c.GetString("keycloak-host-port")),
			Username: c.GetString("keycloak-username"),
			Password: c.GetString("keycloak-password"),
			Timeout:  c.GetDuration("keycloak-timeout"),
		}

		// Elasticsearch
		esAddr  = c.GetString("elasticsearch-host-port")
		esIndex = c.GetString("elasticsearch-index-name")

		// Enabled units
		cockroachEnabled  = c.GetBool("cockroach")
		esEnabled         = c.GetBool("elasticsearch")
		flakiEnabled      = c.GetBool("flaki")
		influxEnabled     = c.GetBool("influx")
		jaegerEnabled     = c.GetBool("jaeger")
		keycloakEnabled   = c.GetBool("keycloak")
		redisEnabled      = c.GetBool("redis")
		sentryEnabled     = c.GetBool("sentry")
		jobEnabled        = c.GetBool("job")
		pprofRouteEnabled = c.GetBool("pprof-route-enabled")

		// Influx
		influxHTTPConfig = influx.HTTPConfig{
			Addr:     fmt.Sprintf("http://%s", c.GetString("influx-host-port")),
			Username: c.GetString("influx-username"),
			Password: c.GetString("influx-password"),
		}
		influxBatchPointsConfig = influx.BatchPointsConfig{
			Precision:        c.GetString("influx-precision"),
			Database:         c.GetString("influx-database"),
			RetentionPolicy:  c.GetString("influx-retention-policy"),
			WriteConsistency: c.GetString("influx-write-consistency"),
		}
		influxWriteInterval = c.GetDuration("influx-write-interval")

		// Jaeger
		jaegerConfig = jaeger.Configuration{
			Disabled: !jaegerEnabled,
			Sampler: &jaeger.SamplerConfig{
				Type:              c.GetString("jaeger-sampler-type"),
				Param:             c.GetFloat64("jaeger-sampler-param"),
				SamplingServerURL: fmt.Sprintf("http://%s", c.GetString("jaeger-sampler-host-port")),
			},
			Reporter: &jaeger.ReporterConfig{
				LogSpans:            c.GetBool("jaeger-reporter-logspan"),
				BufferFlushInterval: c.GetDuration("jaeger-write-interval"),
			},
		}
		jaegerCollectorHealthcheckURL = c.GetString("jaeger-collector-healthcheck-host-port")

		// Sentry
		sentryDSN = c.GetString("sentry-dsn")

		// Redis
		redisURL           = c.GetString("redis-host-port")
		redisPassword      = c.GetString("redis-password")
		redisDatabase      = c.GetInt("redis-database")
		redisWriteInterval = c.GetDuration("redis-write-interval")

		// Cockroach
		cockroachHostPort      = c.GetString("cockroach-host-port")
		cockroachUsername      = c.GetString("cockroach-username")
		cockroachPassword      = c.GetString("cockroach-password")
		cockroachDB            = c.GetString("cockroach-database")
		cockroachCleanInterval = c.GetDuration("cockroach-clean-interval")

		// Jobs
		healthChecksValidity = map[string]time.Duration{
			"cockroach":     c.GetDuration("job-cockroach-health-validity"),
			"elasticsearch": c.GetDuration("job-es-health-validity"),
			"flaki":         c.GetDuration("job-flaki-health-validity"),
			"influx":        c.GetDuration("job-influx-health-validity"),
			"jaeger":        c.GetDuration("job-jaeger-health-validity"),
			"keycloak":      c.GetDuration("job-keycloak-health-validity"),
			"redis":         c.GetDuration("job-redis-health-validity"),
			"sentry":        c.GetDuration("job-sentry-health-validity"),
		}

		// Rate limiting
		rateLimit = map[string]int{
			"event": c.GetInt("rate-event"),
			"user":  c.GetInt("rate-user"),
		}

		// Validation for healthchecks
		validModules = map[string]struct{}{
			"":              struct{}{},
			"cockroach":     struct{}{},
			"elasticsearch": struct{}{},
			"flaki":         struct{}{},
			"influx":        struct{}{},
			"jaeger":        struct{}{},
			"keycloak":      struct{}{},
			"redis":         struct{}{},
			"sentry":        struct{}{},
		}

		healthcheckNames = func(names ...string) map[string]struct{} {
			var m = map[string]struct{}{}
			for _, n := range names {
				m[n] = struct{}{}
			}
			return m
		}
		// Authorized health checks for each module.
		authorizedHC = map[string]map[string]struct{}{
			"cockroach":     healthcheckNames("", "ping"),
			"elasticsearch": healthcheckNames("", "ping"),
			"flaki":         healthcheckNames("", "nextid"),
			"influx":        healthcheckNames("", "ping"),
			"jaeger":        healthcheckNames("", "agent", "collector"),
			"keycloak":      healthcheckNames("", "createuser", "deleteuser"),
			"redis":         healthcheckNames("", "ping"),
			"sentry":        healthcheckNames("", "ping"),
		}
	)

	// Redis.
	type Redis interface {
		Close() error
		Do(commandName string, args ...interface{}) (reply interface{}, err error)
		Send(commandName string, args ...interface{}) error
		Flush() error
	}

	var redisClient Redis = &keycloakb.NoopRedis{}
	if redisEnabled {
		var err error
		redisClient, err = redis.NewResilientConn(redisURL, redisPassword, redisDatabase)
		if err != nil {
			logger.Log("msg", "could not create redis client", "error", err)
			return
		}
		defer redisClient.Close()

		// Create logger that duplicates logs to stdout and redis.
		logger = log.NewJSONLogger(io.MultiWriter(os.Stdout, keycloakb.NewLogstashRedisWriter(redisClient, ComponentName)))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
	}

	// Flaki.
	var flakiClient fb_flaki.FlakiClient = &keycloakb.NoopFlakiClient{}
	if flakiEnabled {
		// Set up a connection to the flaki-service.
		var conn *grpc.ClientConn
		{
			var err error
			conn, err = grpc.Dial(flakiAddr, grpc.WithInsecure(), grpc.WithCodec(flatbuffers.FlatbuffersCodec{}))
			if err != nil {
				logger.Log("msg", "could not connect to flaki-service", "error", err)
				return
			}
			defer conn.Close()
		}

		flakiClient = fb_flaki.NewFlakiClient(conn)

		// Get unique ID for this component
		{
			var b = flatbuffers.NewBuilder(0)
			fb_flaki.FlakiRequestStart(b)
			b.Finish(fb_flaki.FlakiRequestEnd(b))

			var res, err = flakiClient.NextValidID(context.Background(), b)
			if err != nil {
				logger.Log("msg", "could not connect to flaki-service", "error", err)
				return
			}
			ComponentID = string(res.Id())
		}
	}

	// Add component name, component ID and version to the logger tags.
	logger = log.With(logger, "component_name", ComponentName, "component_id", ComponentID, "component_version", Version)

	// Log component version infos.
	logger.Log("environment", Environment, "git_commit", GitCommit)

	// Critical errors channel.
	var errc = make(chan error)
	go func() {
		var c = make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	// Keycloak client.
	var keycloakClient *keycloak.Client
	{
		var err error
		keycloakClient, err = keycloak.New(keycloakConfig)
		if err != nil {
			logger.Log("msg", "could not create Keycloak client", "error", err)
			return
		}
	}

	// Sentry.
	type Sentry interface {
		CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string
		URL() string
		Close()
	}

	var sentryClient Sentry = &keycloakb.NoopSentry{}
	if sentryEnabled {
		var logger = log.With(logger, "unit", "sentry")
		var err error
		sentryClient, err = sentry.New(sentryDSN)
		if err != nil {
			logger.Log("msg", "could not create Sentry client", "error", err)
			return
		}
		defer sentryClient.Close()
	}

	// Influx client.
	type Metrics interface {
		NewCounter(name string) metrics.Counter
		NewGauge(name string) metrics.Gauge
		NewHistogram(name string) metrics.Histogram
		WriteLoop(c <-chan time.Time)
		Write(bp influx.BatchPoints) error
		Ping(timeout time.Duration) (time.Duration, string, error)
	}

	var influxMetrics Metrics = &keycloakb.NoopMetrics{}
	if influxEnabled {
		var logger = log.With(logger, "unit", "influx")

		var influxClient, err = influx.NewHTTPClient(influxHTTPConfig)
		if err != nil {
			logger.Log("msg", "could not create Influx client", "error", err)
			return
		}
		defer influxClient.Close()

		var gokitInflux = gokit_influx.New(
			map[string]string{},
			influxBatchPointsConfig,
			log.With(logger, "unit", "go-kit influx"),
		)

		influxMetrics = keycloakb.NewMetrics(influxClient, gokitInflux)
	}

	// Jaeger client.
	var tracer opentracing.Tracer
	{
		var logger = log.With(logger, "unit", "jaeger")
		var closer io.Closer
		var err error

		tracer, closer, err = jaegerConfig.New(ComponentName)
		if err != nil {
			logger.Log("msg", "could not create Jaeger tracer", "error", err)
			return
		}
		defer closer.Close()
	}

	// Cockroach DB.
	type Cockroach interface {
		Exec(query string, args ...interface{}) (sql.Result, error)
		Ping() error
		Query(query string, args ...interface{}) (*sql.Rows, error)
		QueryRow(query string, args ...interface{}) *sql.Row
	}

	var cockroachConn Cockroach = keycloakb.NoopCockroach{}
	if cockroachEnabled {
		var err error
		cockroachConn, err = sql.Open("postgres", fmt.Sprintf("postgresql://%s:%s@%s/%s?sslmode=disable", cockroachUsername, cockroachPassword, cockroachHostPort, cockroachDB))
		if err != nil {
			logger.Log("msg", "could not create cockroach DB connection for config DB", "error", err)
			return
		}
	}

	// Elasticsearch client.
	var esClient = elasticsearch.NewClient(esAddr, http.DefaultClient)

	// User service.
	var userEndpoints = user.Endpoints{}
	{
		var userLogger = log.With(logger, "svc", "user")

		var userModule user.Module
		{
			userModule = user.NewModule(keycloakClient)
			userModule = user.MakeModuleInstrumentingMW(influxMetrics.NewHistogram("user_module"))(userModule)
			userModule = user.MakeModuleLoggingMW(log.With(userLogger, "mw", "module"))(userModule)
			userModule = user.MakeModuleTracingMW(tracer)(userModule)
		}

		var userComponent user.Component
		{
			userComponent = user.NewComponent(userModule)
			userComponent = user.MakeComponentInstrumentingMW(influxMetrics.NewHistogram("user_component"))(userComponent)
			userComponent = user.MakeComponentLoggingMW(log.With(userLogger, "mw", "component"))(userComponent)
			userComponent = user.MakeComponentTracingMW(tracer)(userComponent)
			userComponent = user.MakeComponentTrackingMW(sentryClient, log.With(userLogger, "mw", "component"))(userComponent)
		}

		var userEndpoint endpoint.Endpoint
		{
			userEndpoint = user.MakeGetUsersEndpoint(userComponent)
			userEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("user_endpoint"))(userEndpoint)
			userEndpoint = middleware.MakeEndpointLoggingMW(log.With(userLogger, "mw", "endpoint", "unit", "getusers"))(userEndpoint)
			userEndpoint = middleware.MakeEndpointTracingMW(tracer, "user_endpoint")(userEndpoint)
		}
		// Rate limiting
		userEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["user"]))(userEndpoint)

		userEndpoints = user.Endpoints{
			Endpoint: userEndpoint,
		}
	}

	// Event service.
	var eventEndpoints = event.Endpoints{}
	{
		var eventLogger = log.With(logger, "svc", "event")

		var consoleModule event.ConsoleModule
		{
			consoleModule = event.NewConsoleModule(log.With(eventLogger, "module", "console"), esClient, esIndex, ComponentName, ComponentID)
			consoleModule = event.MakeConsoleModuleInstrumentingMW(influxMetrics.NewHistogram("console_module"))(consoleModule)
			consoleModule = event.MakeConsoleModuleLoggingMW(log.With(eventLogger, "mw", "module", "unit", "console"))(consoleModule)
			consoleModule = event.MakeConsoleModuleTracingMW(tracer)(consoleModule)
		}

		var statisticModule event.StatisticModule
		{
			statisticModule = event.NewStatisticModule(influxMetrics, influxBatchPointsConfig)
			statisticModule = event.MakeStatisticModuleInstrumentingMW(influxMetrics.NewHistogram("statistic_module"))(statisticModule)
			statisticModule = event.MakeStatisticModuleLoggingMW(log.With(eventLogger, "mw", "module", "unit", "statistic"))(statisticModule)
			statisticModule = event.MakeStatisticModuleTracingMW(tracer)(statisticModule)
		}

		var eventAdminComponent event.AdminComponent
		{
			var fns = []event.FuncEvent{consoleModule.Print, statisticModule.Stats}
			eventAdminComponent = event.NewAdminComponent(fns, fns, fns, fns)
			eventAdminComponent = event.MakeAdminComponentInstrumentingMW(influxMetrics.NewHistogram("admin_component"))(eventAdminComponent)
			eventAdminComponent = event.MakeAdminComponentLoggingMW(log.With(eventLogger, "mw", "component", "unit", "admin_event"))(eventAdminComponent)
			eventAdminComponent = event.MakeAdminComponentTracingMW(tracer)(eventAdminComponent)
		}

		var eventComponent event.Component
		{
			var fns = []event.FuncEvent{consoleModule.Print, statisticModule.Stats}
			eventComponent = event.NewComponent(fns, fns)
			eventComponent = event.MakeComponentInstrumentingMW(influxMetrics.NewHistogram("component"))(eventComponent)
			eventComponent = event.MakeComponentLoggingMW(log.With(eventLogger, "mw", "component", "unit", "event"))(eventComponent)
			eventComponent = event.MakeComponentTracingMW(tracer)(eventComponent)
		}

		var muxComponent event.MuxComponent
		{
			muxComponent = event.NewMuxComponent(eventComponent, eventAdminComponent)
			muxComponent = event.MakeMuxComponentInstrumentingMW(influxMetrics.NewHistogram("mux_component"))(muxComponent)
			muxComponent = event.MakeMuxComponentLoggingMW(log.With(eventLogger, "mw", "component", "unit", "mux"))(muxComponent)
			muxComponent = event.MakeMuxComponentTracingMW(tracer)(muxComponent)
			muxComponent = event.MakeMuxComponentTrackingMW(sentryClient, log.With(eventLogger, "mw", "component"))(muxComponent)
		}

		var eventEndpoint endpoint.Endpoint
		{
			eventEndpoint = event.MakeEventEndpoint(muxComponent)
			eventEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("event_endpoint"))(eventEndpoint)
			eventEndpoint = middleware.MakeEndpointLoggingMW(log.With(eventLogger, "mw", "endpoint"))(eventEndpoint)
			eventEndpoint = middleware.MakeEndpointTracingMW(tracer, "event_endpoint")(eventEndpoint)
		}

		// Rate limiting
		eventEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["event"]))(eventEndpoint)

		eventEndpoints = event.Endpoints{
			Endpoint: eventEndpoint,
		}
	}
	// Export configuration
	var exportModule = export.NewModule(keycloakClient)
	var cfgStorageModue = export.NewConfigStorageModule(cockroachConn)

	var exportComponent = export.NewComponent(ComponentName, Version, exportModule, cfgStorageModue)
	var exportEndpoint = export.MakeExportEndpoint(exportComponent)
	var exportSaveAndExportEndpoint = export.MakeStoreAndExportEndpoint(exportComponent)

	// Health service.
	var healthEndpoints = health.Endpoints{}
	{
		var healthLogger = log.With(logger, "svc", "health")

		type HealthCheckStorage interface {
			Read(ctx context.Context, module, healthcheck string) (json.RawMessage, error)
			Update(ctx context.Context, module string, jsonReports json.RawMessage, validity time.Duration) error
			Clean() error
		}

		var healthStorage HealthCheckStorage
		{
			healthStorage = health.NewStorageModule(ComponentName, ComponentID, cockroachConn)
		}

		type HealthChecker interface {
			HealthCheck(context.Context, string) (json.RawMessage, error)
		}
		var cockroachHM HealthChecker
		{
			cockroachHM = common.NewCockroachModule(cockroachConn, cockroachEnabled)
			cockroachHM = common.MakeHealthCheckerLoggingMW(log.With(healthLogger, "module", "cockroach"))(cockroachHM)
			cockroachHM = common.MakeValidationMiddleware(authorizedHC["cockroach"])(cockroachHM)
		}
		var influxHM HealthChecker
		{
			influxHM = common.NewInfluxModule(influxMetrics, influxEnabled)
			influxHM = common.MakeHealthCheckerLoggingMW(log.With(healthLogger, "module", "influx"))(influxHM)
			influxHM = common.MakeValidationMiddleware(authorizedHC["influx"])(influxHM)
		}
		var jaegerHM HealthChecker
		{
			jaegerHM = common.NewJaegerModule(http.DefaultClient, jaegerCollectorHealthcheckURL, jaegerEnabled)
			jaegerHM = common.MakeHealthCheckerLoggingMW(log.With(healthLogger, "module", "jaeger"))(jaegerHM)
			jaegerHM = common.MakeValidationMiddleware(authorizedHC["jaeger"])(jaegerHM)

		}
		var redisHM HealthChecker
		{
			redisHM = common.NewRedisModule(redisClient, redisEnabled)
			redisHM = common.MakeHealthCheckerLoggingMW(log.With(healthLogger, "module", "redis"))(redisHM)
			redisHM = common.MakeValidationMiddleware(authorizedHC["redis"])(redisHM)
		}
		var sentryHM HealthChecker
		{
			sentryHM = common.NewSentryModule(sentryClient, http.DefaultClient, sentryEnabled)
			sentryHM = common.MakeHealthCheckerLoggingMW(log.With(healthLogger, "module", "sentry"))(sentryHM)
			sentryHM = common.MakeValidationMiddleware(authorizedHC["sentry"])(sentryHM)
		}
		var flakiHM HealthChecker
		{
			flakiHM = common.NewFlakiModule(&flakiHealthClient{flakiClient}, flakiEnabled)
			flakiHM = common.MakeHealthCheckerLoggingMW(log.With(healthLogger, "module", "flaki"))(flakiHM)
			flakiHM = common.MakeValidationMiddleware(authorizedHC["flaki"])(flakiHM)
		}
		var elasticsearchHM HealthChecker
		{
			elasticsearchHM = health.NewElasticsearchModule(http.DefaultClient, esAddr, esEnabled)
			elasticsearchHM = common.MakeHealthCheckerLoggingMW(log.With(healthLogger, "module", "elasticsearch"))(elasticsearchHM)
			elasticsearchHM = common.MakeValidationMiddleware(authorizedHC["elasticsearch"])(elasticsearchHM)
		}
		var keycloakHM HealthChecker
		{
			var err error
			keycloakHM, err = health.NewKeycloakModule(keycloakClient, Version, keycloakEnabled)
			if err != nil {
				logger.Log("msg", "could not create keycloak health check module", "error", err)
				return
			}
		}

		var healthCheckers = map[string]health.HealthChecker{
			"cockroach":     cockroachHM,
			"elasticsearch": elasticsearchHM,
			"flaki":         flakiHM,
			"influx":        influxHM,
			"jaeger":        jaegerHM,
			"keycloak":      keycloakHM,
			"redis":         redisHM,
			"sentry":        sentryHM,
		}

		var healthComponent health.HealthCheckers
		{
			healthComponent = health.NewComponent(healthCheckers, healthChecksValidity, healthStorage)
			healthComponent = health.MakeComponentLoggingMW(log.With(healthLogger, "mw", "component"))(healthComponent)
			healthComponent = health.MakeValidationMiddleware(validModules)(healthComponent)
		}

		var healthChecksEndpoint endpoint.Endpoint
		{
			healthChecksEndpoint = health.MakeHealthChecksEndpoint(healthComponent)
			healthChecksEndpoint = health.MakeEndpointLoggingMW(log.With(healthLogger, "mw", "endpoint", "unit", "HealthChecks"))(healthChecksEndpoint)
		}

		healthEndpoints = health.Endpoints{
			HealthCheckEndpoint: healthChecksEndpoint,
		}

		// Jobs
		if jobEnabled {
			var ctrl = controller.NewController(ComponentName, ComponentID, idgenerator.New(flakiClient, tracer), &job_lock.NoopLocker{}, controller.EnableStatusStorage(job_status.New(cockroachConn)))

			for _, job := range []string{"cockroach", "elasticsearch", "flaki", "influx", "jaeger", "keycloak", "redis", "sentry"} {
				var job, err = health_job.MakeHealthJob(healthCheckers[job], job, healthChecksValidity[job], healthStorage, logger)
				if err != nil {
					logger.Log("msg", fmt.Sprintf("could not create %s health job", job), "error", err)
					return
				}
				ctrl.Register(job)
				ctrl.Schedule("@minutely", job.Name())
			}

			var cleanJob *job.Job
			{
				var err error
				cleanJob, err = health_job.MakeStorageCleaningJob(healthStorage, log.With(logger, "job", "clean health checks"))
				if err != nil {
					logger.Log("msg", "could not create clean job", "error", err)
					return
				}
				ctrl.Register(cleanJob)
				ctrl.Schedule(fmt.Sprintf("@every %s", cockroachCleanInterval), cleanJob.Name())

			}
			ctrl.Start()
		}
	}

	// GRPC server.
	go func() {
		var logger = log.With(logger, "transport", "grpc")
		logger.Log("addr", grpcAddr)

		var lis net.Listener
		{
			var err error
			lis, err = net.Listen("tcp", grpcAddr)
			if err != nil {
				logger.Log("msg", "could not initialise listener", "error", err)
				errc <- err
				return
			}
		}

		// User Handler.
		var getUsersHandler grpc_transport.Handler
		{
			getUsersHandler = user.MakeGRPCGetUsersHandler(userEndpoints.Endpoint)
			getUsersHandler = middleware.MakeGRPCCorrelationIDMW(flakiClient, tracer, logger, ComponentName, ComponentID)(getUsersHandler)
			getUsersHandler = middleware.MakeGRPCTracingMW(tracer, ComponentName, "grpc_server_getusers")(getUsersHandler)
		}

		var grpcServer = user.NewGRPCServer(getUsersHandler)
		var userServer = grpc.NewServer(grpc.CustomCodec(flatbuffers.FlatbuffersCodec{}))
		fb.RegisterUserServiceServer(userServer, grpcServer)

		errc <- userServer.Serve(lis)
	}()

	// HTTP Server.
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Log("addr", httpAddr)

		var route = mux.NewRouter()

		// Version.
		route.Handle("/", http.HandlerFunc(makeVersion(ComponentName, ComponentID, Version, Environment, GitCommit)))

		// Event.
		var eventSubroute = route.PathPrefix("/event").Subrouter()

		var eventHandler http.Handler
		{
			eventHandler = event.MakeHTTPEventHandler(eventEndpoints.Endpoint)
			eventHandler = middleware.MakeHTTPCorrelationIDMW(flakiClient, tracer, logger, ComponentName, ComponentID)(eventHandler)
			eventHandler = middleware.MakeHTTPTracingMW(tracer, ComponentName, "http_server_event")(eventHandler)
		}
		eventSubroute.Handle("/receiver", eventHandler)

		// Users.
		var getUsersHandler http.Handler
		{
			getUsersHandler = user.MakeHTTPGetUsersHandler(userEndpoints.Endpoint)
			getUsersHandler = middleware.MakeHTTPCorrelationIDMW(flakiClient, tracer, logger, ComponentName, ComponentID)(getUsersHandler)
			getUsersHandler = middleware.MakeHTTPTracingMW(tracer, ComponentName, "http_server_getusers")(getUsersHandler)
		}
		route.Handle("/getusers", getUsersHandler)

		// Export.
		route.Handle("/export", export.MakeHTTPExportHandler(exportEndpoint)).Methods("GET")
		route.Handle("/export", export.MakeHTTPExportHandler(exportSaveAndExportEndpoint)).Methods("POST")

		// Health checks.
		var healthHandler http.Handler
		{
			healthHandler = health.MakeHealthCheckHandler(healthEndpoints.HealthCheckEndpoint)
			healthHandler = middleware.MakeHTTPCorrelationIDMW(flakiClient, tracer, logger, ComponentName, ComponentID)(healthHandler)
		}

		route.Path("/health").Handler(healthHandler)
		route.Path("/health/{module}").Handler(healthHandler)
		route.Path("/health/{module}/{healthcheck}").Handler(healthHandler)
		route.Path("/health").Queries("nocache", "{nocache}").Handler(healthHandler)
		route.Path("/health/{module}").Queries("nocache", "{nocache}").Handler(healthHandler)
		route.Path("/health/{module}/{healthcheck}").Queries("nocache", "{nocache}").Handler(healthHandler)

		// Debug.
		if pprofRouteEnabled {
			var debugSubroute = route.PathPrefix("/debug").Subrouter()
			debugSubroute.HandleFunc("/pprof/", http.HandlerFunc(pprof.Index))
			debugSubroute.HandleFunc("/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
			debugSubroute.HandleFunc("/pprof/profile", http.HandlerFunc(pprof.Profile))
			debugSubroute.HandleFunc("/pprof/symbol", http.HandlerFunc(pprof.Symbol))
			debugSubroute.HandleFunc("/pprof/trace", http.HandlerFunc(pprof.Trace))
		}

		errc <- http.ListenAndServe(httpAddr, route)
	}()

	// Influx writing.
	go func() {
		var tic = time.NewTicker(influxWriteInterval)
		defer tic.Stop()
		influxMetrics.WriteLoop(tic.C)
	}()

	// Redis writing.
	if redisEnabled {
		go func() {
			var tic = time.NewTicker(redisWriteInterval)
			defer tic.Stop()
			for range tic.C {
				redisClient.Flush()
			}
		}()
	}

	logger.Log("error", <-errc)
}

type flakiHealthClient struct {
	client fb_flaki.FlakiClient
}

func (hc *flakiHealthClient) NextID(ctx context.Context) (string, error) {
	var b = flatbuffers.NewBuilder(0)
	fb_flaki.FlakiRequestStart(b)
	b.Finish(fb_flaki.FlakiRequestEnd(b))

	var reply *fb_flaki.FlakiReply
	{
		var err error
		reply, err = hc.client.NextValidID(ctx, b)
		if err != nil {
			return "", err
		}
	}

	return string(reply.Id()), nil
}

// makeVersion makes a HTTP handler that returns information about the version of the bridge.
func makeVersion(componentName, ComponentID, version, environment, gitCommit string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		var info = struct {
			Name    string `json:"name"`
			ID      string `json:"id"`
			Version string `json:"version"`
			Env     string `json:"environment"`
			Commit  string `json:"commit"`
		}{
			Name:    ComponentName,
			ID:      ComponentID,
			Version: version,
			Env:     environment,
			Commit:  gitCommit,
		}

		var j, err = json.MarshalIndent(info, "", "  ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	}
}

func config(logger log.Logger) *viper.Viper {
	logger.Log("msg", "load configuration and command args")

	var v = viper.New()

	// Component default.
	v.SetDefault("config-file", "./configs/keycloak_bridge.yml")
	v.SetDefault("component-http-host-port", "0.0.0.0:8888")
	v.SetDefault("component-grpc-host-port", "0.0.0.0:5555")

	// Flaki default.
	v.SetDefault("flaki", true)
	v.SetDefault("flaki-host-port", "")

	// Keycloak default.
	v.SetDefault("keycloak", true)
	v.SetDefault("keycloak-host-port", "127.0.0.1:8080")
	v.SetDefault("keycloak-username", "")
	v.SetDefault("keycloak-password", "")
	v.SetDefault("keycloak-timeout", "5s")

	// Elasticsearch default.
	v.SetDefault("elasticsearch", false)
	v.SetDefault("elasticsearch-host-port", "elasticsearch:9200")
	v.SetDefault("elasticsearch-index-name", "keycloak_business")

	// Influx DB client default.
	v.SetDefault("influx", false)
	v.SetDefault("influx-host-port", "")
	v.SetDefault("influx-username", "")
	v.SetDefault("influx-password", "")
	v.SetDefault("influx-database", "")
	v.SetDefault("influx-precision", "")
	v.SetDefault("influx-retention-policy", "")
	v.SetDefault("influx-write-consistency", "")
	v.SetDefault("influx-write-interval", "1s")

	// Sentry client default.
	v.SetDefault("sentry", false)
	v.SetDefault("sentry-dsn", "")

	// Jaeger tracing default.
	v.SetDefault("jaeger", false)
	v.SetDefault("jaeger-sampler-type", "")
	v.SetDefault("jaeger-sampler-param", 0)
	v.SetDefault("jaeger-sampler-host-port", "")
	v.SetDefault("jaeger-reporter-logspan", false)
	v.SetDefault("jaeger-write-interval", "1s")
	v.SetDefault("jaeger-collector-healthcheck-host-port", "")

	// Debug routes enabled.
	v.SetDefault("pprof-route-enabled", true)

	// Redis.
	v.SetDefault("redis", false)
	v.SetDefault("redis-host-port", "")
	v.SetDefault("redis-password", "")
	v.SetDefault("redis-database", 0)
	v.SetDefault("redis-write-interval", "1s")

	// Cockroach.
	v.SetDefault("cockroach", false)
	v.SetDefault("cockroach-host-port", "")
	v.SetDefault("cockroach-username", "")
	v.SetDefault("cockroach-password", "")
	v.SetDefault("cockroach-database", "")
	v.SetDefault("cockroach-clean-interval", "24h")

	// Jobs
	v.SetDefault("job", false)
	v.SetDefault("job-flaki-health-validity", "1m")
	v.SetDefault("job-influx-health-validity", "1m")
	v.SetDefault("job-jaeger-health-validity", "1m")
	v.SetDefault("job-redis-health-validity", "1m")
	v.SetDefault("job-sentry-health-validity", "1m")
	v.SetDefault("job-keycloak-health-validity", "1m")

	// Rate limiting (in requests/second)
	v.SetDefault("rate-event", 1000)
	v.SetDefault("rate-user", 1000)

	// First level of override.
	pflag.String("config-file", v.GetString("config-file"), "The configuration file path can be relative or absolute.")
	v.BindPFlag("config-file", pflag.Lookup("config-file"))
	pflag.Parse()

	// Load and log config.
	v.SetConfigFile(v.GetString("config-file"))
	var err = v.ReadInConfig()
	if err != nil {
		logger.Log("error", err)
	}

	// If the host/port is not set, we consider the components deactivated.
	v.Set("elasticsearch", v.GetString("es-host-port") != "")
	v.Set("influx", v.GetString("influx-host-port") != "")
	v.Set("sentry", v.GetString("sentry-dsn") != "")
	v.Set("jaeger", v.GetString("jaeger-sampler-host-port") != "")
	v.Set("redis", v.GetString("redis-host-port") != "")
	v.Set("cockroach", v.GetString("cockroach-host-port") != "")

	// Log config in alphabetical order.
	var keys = v.AllKeys()
	sort.Strings(keys)

	for _, k := range keys {
		logger.Log(k, v.Get(k))
	}
	return v
}