package statistics

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// Component is the interface of the events component.
type Component interface {
	GetStatistics(context.Context, string) (api.StatisticsRepresentation, error)
	GetStatisticsUsers(context.Context, string) (api.StatisticsUsersRepresentation, error)
	GetStatisticsAuthenticators(context.Context, string) (map[string]int64, error)
	GetStatisticsAuthentications(context.Context, string, string) ([][]int64, error)
	GetStatisticsAuthenticationsLog(context.Context, string, string) ([]api.StatisticsConnectionRepresentation, error)
	GetMigrationReport(context.Context, string) (map[string]bool, error)
}

type KeycloakClient interface {
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	GetStatisticsUsers(accessToken string, realmName string) (kc.StatisticsUsersRepresentation, error)
	GetStatisticsAuthenticators(accessToken string, realmName string) (map[string]int64, error)
}

type component struct {
	db             keycloakb.EventsDBModule
	keycloakClient KeycloakClient
	logger         log.Logger
}

// NewComponent returns a component
func NewComponent(db keycloakb.EventsDBModule, keycloakClient KeycloakClient, logger log.Logger) Component {
	return &component{
		db:             db,
		keycloakClient: keycloakClient,
		logger:         logger,
	}
}

// Grabs statistics
func (ec *component) GetStatistics(ctx context.Context, realmName string) (api.StatisticsRepresentation, error) {
	var res api.StatisticsRepresentation
	var err error

	res.LastConnection, err = ec.db.GetLastConnection(ctx, realmName)

	if err == nil {
		res.TotalConnections.LastTwelveHours, err = ec.db.GetTotalConnectionsCount(ctx, realmName, "12 HOUR")
	}
	if err == nil {
		res.TotalConnections.LastDay, err = ec.db.GetTotalConnectionsCount(ctx, realmName, "1 DAY")
	}
	if err == nil {
		res.TotalConnections.LastWeek, err = ec.db.GetTotalConnectionsCount(ctx, realmName, "1 WEEK")
	}
	if err == nil {
		res.TotalConnections.LastMonth, err = ec.db.GetTotalConnectionsCount(ctx, realmName, "1 MONTH")
	}
	if err == nil {
		res.TotalConnections.LastYear, err = ec.db.GetTotalConnectionsCount(ctx, realmName, "1 YEAR")
	}

	return res, err
}

// GetStatisticsUsers gives  statistics on the total number of users and on those that are inactive or disabled
func (ec *component) GetStatisticsUsers(ctx context.Context, realmName string) (api.StatisticsUsersRepresentation, error) {
	var err error
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	res, err := ec.keycloakClient.GetStatisticsUsers(accessToken, realmName)

	if err != nil {
		ec.logger.Warn("err", err.Error())
		return api.StatisticsUsersRepresentation{}, err
	}
	return api.ConvertToAPIStatisticsUsers(res), nil
}

// GetStatisticsAuthenticators gives  statistics on the types of authenticators used by the users of a certain realm
func (ec *component) GetStatisticsAuthenticators(ctx context.Context, realmName string) (map[string]int64, error) {
	var err error
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	res, err := ec.keycloakClient.GetStatisticsAuthenticators(accessToken, realmName)

	if err != nil {
		ec.logger.Warn("err", err.Error())
		return nil, err
	}
	return res, nil
}

// GetStatisticsAuthentications gives statistics on number of authentications on a certain period
func (ec *component) GetStatisticsAuthentications(ctx context.Context, realmName string, unit string) ([][]int64, error) {

	var res [][]int64
	var err error
	// query to get number of authentications
	switch unit {
	case "hours":
		res, err = ec.db.GetTotalConnectionsHoursCount(ctx, realmName)
	case "days":
		res, err = ec.db.GetTotalConnectionsDaysCount(ctx, realmName)
	case "months":
		res, err = ec.db.GetTotalConnectionsMonthsCount(ctx, realmName)
	default:
		ec.logger.Warn("err", "Invalid parameter value")
		return nil, errorhandler.CreateInvalidQueryParameterError(internal.Unit)
	}
	if err != nil {
		ec.logger.Warn("err", err.Error())
		return nil, err
	}

	return res, nil
}

// GetStatisticsAuthenticationsLog gives statistics on the last authentications of a user
func (ec *component) GetStatisticsAuthenticationsLog(ctx context.Context, realmName string, max string) ([]api.StatisticsConnectionRepresentation, error) {

	var res []api.StatisticsConnectionRepresentation
	//var err error
	// query to get number of authentications

	res, err := ec.db.GetLastConnections(ctx, realmName, max)
	if err != nil {
		ec.logger.Warn("err", err.Error())
		return nil, err
	}

	return res, nil
}

// Compute Migration Report
func (ec *component) GetMigrationReport(ctx context.Context, realmName string) (map[string]bool, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)

	var paramKV = []string{}
	paramKV = append(paramKV, "max", "0") //All

	usersKc, err := ec.keycloakClient.GetUsers(accessToken, ctxRealm, realmName, paramKV...)

	if err != nil {
		ec.logger.Warn("err", err.Error())
		return map[string]bool{}, err
	}

	var migratedUsers = map[string]bool{}

	for _, user := range usersKc.Users {
		migratedUsers[*user.Username] = isMigrated(user)
	}

	return migratedUsers, nil
}

func isMigrated(user kc.UserRepresentation) bool {
	if user.Attributes == nil {
		return false
	}

	var attributes = *(user.Attributes)

	if len(attributes["migrated"]) != 0 && attributes["migrated"][0] == "true" {
		return true
	}

	return false
}
