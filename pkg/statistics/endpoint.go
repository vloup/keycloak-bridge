package statistics

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	errorhandler "github.com/cloudtrust/common-service/errors"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints exposed for path /events
type Endpoints struct {
	GetStatistics                   endpoint.Endpoint
	GetStatisticsUsers              endpoint.Endpoint
	GetStatisticsAuthenticators     endpoint.Endpoint
	GetStatisticsAuthentications    endpoint.Endpoint
	GetStatisticsAuthenticationsLog endpoint.Endpoint
	GetMigrationReport              endpoint.Endpoint
}

// MakeGetStatisticsEndpoint makes the statistic summary endpoint.
func MakeGetStatisticsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetStatistics(ctx, m["realm"])
	}
}

// MakeGetStatisticsUsersEndpoint makes the statistic users summary endpoint.
func MakeGetStatisticsUsersEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetStatisticsUsers(ctx, m["realm"])
	}
}

// MakeGetStatisticsAuthenticatorsEndpoint makes the statistic authenticators summary endpoint.
func MakeGetStatisticsAuthenticatorsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetStatisticsAuthenticators(ctx, m["realm"])
	}
}

// MakeGetStatisticsAuthenticatorsEndpoint makes the statistic authentications per period summary endpoint.
func MakeGetStatisticsAuthenticationsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		_, ok := m["unit"]
		if !ok {
			return nil, errorhandler.CreateMissingParameterError(internal.Unit)
		}
		return ec.GetStatisticsAuthentications(ctx, m["realm"], m["unit"])
	}
}

// MakeGetStatisticsAuthenticatorsEndpoint makes the statistic last authentications summary endpoint.
func MakeGetStatisticsAuthenticationsLogEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		if !ok {
			return nil, errorhandler.CreateMissingParameterError(internal.Max)
		}
		return ec.GetStatisticsAuthenticationsLog(ctx, m["realm"], m["max"])
	}
}

// MakeGetMigrationReportEndpoint makes the migration reporting endpoint.
func MakeGetMigrationReportEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetMigrationReport(ctx, m["realm"])
	}
}
