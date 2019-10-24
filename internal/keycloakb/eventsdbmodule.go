package keycloakb

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	errorhandler "github.com/cloudtrust/common-service/errors"

	"github.com/cloudtrust/common-service/database"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	api_stat "github.com/cloudtrust/keycloak-bridge/api/statistics"
)

// EventsDBModule is the interface of the audit events module.
type EventsDBModule interface {
	GetEventsCount(context.Context, map[string]string) (int, error)
	GetEvents(context.Context, map[string]string) ([]api.AuditRepresentation, error)
	GetEventsSummary(context.Context) (api.EventSummaryRepresentation, error)
	GetLastConnection(context.Context, string) (int64, error)
	GetTotalConnectionsCount(context.Context, string, string) (int64, error)
	GetTotalConnectionsHoursCount(context.Context, string) ([][]int64, error)
	GetTotalConnectionsDaysCount(context.Context, string) ([][]int64, error)
	GetTotalConnectionsMonthsCount(context.Context, string) ([][]int64, error)
	GetLastConnections(context.Context, string, string) ([]api_stat.StatisticsConnectionRepresentation, error)
}

type eventsDBModule struct {
	db database.CloudtrustDB
}

// NewEventsDBModule returns an events database module.
func NewEventsDBModule(db database.CloudtrustDB) EventsDBModule {
	return &eventsDBModule{
		db: db,
	}
}

type selectAuditEventsParameters struct {
	origin      interface{}
	realm       interface{}
	userID      interface{}
	ctEventType interface{}
	dateFrom    interface{}
	dateTo      interface{}
	first       interface{}
	max         interface{}
	exclude     interface{}
}

const (
	whereAuditEvents = `
	WHERE origin = IFNULL(?, origin)
	AND realm_name = IFNULL(?, realm_name)
	AND user_id = IFNULL(?, user_id)
	AND ct_event_type = IFNULL(?, ct_event_type)
	AND unix_timestamp(audit_time) between IFNULL(?, unix_timestamp(audit_time)) and IFNULL(?, unix_timestamp(audit_time))
	AND ct_event_type <> IFNULL(?, 'not-a-ct-event-type')
	`

	selectAuditEventsStmt = `SELECT audit_id, unix_timestamp(audit_time), origin, realm_name, agent_user_id, agent_username, agent_realm_name,
	                            user_id, username, ct_event_type, kc_event_type, kc_operation_type, client_id, additional_info
		FROM audit ` + whereAuditEvents + `		
		ORDER BY audit_time DESC
		LIMIT ?, ?;
		`
	selectCountAuditEventsStmt        = `SELECT count(1) FROM audit ` + whereAuditEvents
	selectLastConnectionTimeStmt      = `SELECT ifnull(unix_timestamp(max(audit_time)), 0) FROM audit WHERE realm_name=? AND ct_event_type='LOGON_OK'`
	selectAuditSummaryRealmStmt       = `SELECT distinct realm_name FROM audit;`
	selectAuditSummaryOriginStmt      = `SELECT distinct origin FROM audit;`
	selectAuditSummaryCtEventTypeStmt = `SELECT distinct ct_event_type FROM audit;`
	selectConnectionsCount            = `SELECT count(1) FROM audit WHERE realm_name=? AND ct_event_type='LOGON_OK' AND date_add(audit_time, INTERVAL ##INTERVAL##)>now()`
	selectConnectionsHoursCount       = `SELECT count(1) FROM audit WHERE realm_name=? AND ct_event_type='LOGON_OK' 
										AND date_add(audit_time, INTERVAL 24 HOUR) > date_add(UTC_TIMESTAMP, INTERVAL (3600 - second(UTC_TIMESTAMP)) SECOND)
										AND HOUR(audit_time) = HOUR(DATE_SUB(UTC_TIMESTAMP, INTERVAL ##OFFSET## HOUR));`
	selectConnectionsDaysCount = `SELECT count(1) FROM audit WHERE realm_name=? AND ct_event_type='LOGON_OK' 
										AND date_add(audit_time, INTERVAL 30 DAY) > date_add(UTC_TIMESTAMP, INTERVAL (86400 - second(UTC_TIMESTAMP) - 60*MINUTE(UTC_TIMESTAMP) - 3600*HOUR(UTC_TIMESTAMP)) SECOND)
										AND DAY(audit_time) = DAY(DATE_SUB(UTC_TIMESTAMP, INTERVAL ##OFFSET## DAY));`
	selectConnectionsMonthsCount = `SELECT count(1) FROM audit WHERE realm_name=? AND ct_event_type='LOGON_OK' 
										AND date_add(audit_time, INTERVAL 12 MONTH) > date_format(date_add(UTC_TIMESTAMP, INTERVAL 1 MONTH), '%Y-%m-01')
										AND MONTH(audit_time) = MONTH(DATE_SUB(UTC_TIMESTAMP, INTERVAL ##OFFSET## MONTH));`
	selectConnectionStmt = `SELECT unix_timestamp(audit_time), ct_event_type, username, additional_info 
							FROM audit WHERE realm_name=? AND (ct_event_type='LOGON_OK' OR ct_event_type='LOGON_ERROR') 	
							ORDER BY audit_time DESC
							LIMIT ?;
				`
)

func createAuditEventsParametersFromMap(m map[string]string) (selectAuditEventsParameters, error) {
	res := selectAuditEventsParameters{
		origin:      getSQLParam(m, "origin", nil),
		realm:       getSQLParam(m, "realm", nil),
		userID:      getSQLParam(m, "userID", nil),
		ctEventType: getSQLParam(m, "ctEventType", nil),
		dateFrom:    getSQLParam(m, "dateFrom", nil),
		dateTo:      getSQLParam(m, "dateTo", nil),
		first:       getSQLParam(m, "first", 0),
		max:         getSQLParam(m, "max", 500),
		exclude:     getSQLParam(m, "exclude", nil),
	}
	if res.exclude != nil && strings.Contains(res.exclude.(string), ",") {
		// Multiple values are not supported yet
		return res, errorhandler.CreateInvalidQueryParameterError(Exclude)
	}
	return res, nil
}

// GetEvents gets the count of events matching some criterias (dateFrom, dateTo, realm, ...)
func (cm *eventsDBModule) GetEventsCount(_ context.Context, m map[string]string) (int, error) {
	params, err := createAuditEventsParametersFromMap(m)
	if err != nil {
		return 0, err
	}

	var count int
	row := cm.db.QueryRow(selectCountAuditEventsStmt, params.origin, params.realm, params.userID, params.ctEventType, params.dateFrom, params.dateTo, params.exclude)
	err = row.Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetEvents gets the events matching some criterias (dateFrom, dateTo, realm, ...)
func (cm *eventsDBModule) GetEvents(_ context.Context, m map[string]string) ([]api.AuditRepresentation, error) {
	var res = []api.AuditRepresentation{}
	params, errParams := createAuditEventsParametersFromMap(m)
	if errParams != nil {
		return nil, errParams
	}

	rows, err := cm.db.Query(selectAuditEventsStmt, params.origin, params.realm, params.userID, params.ctEventType, params.dateFrom, params.dateTo, params.exclude, params.first, params.max)
	if err != nil {
		return res, err
	}
	defer rows.Close()

	for rows.Next() {
		var dba api.DbAuditRepresentation
		err = rows.Scan(&dba.AuditID, &dba.AuditTime, &dba.Origin, &dba.RealmName, &dba.AgentUserID, &dba.AgentUsername, &dba.AgentRealmName,
			&dba.UserID, &dba.Username, &dba.CtEventType, &dba.KcEventType, &dba.KcOperationType, &dba.ClientID, &dba.AdditionalInfo)
		if err != nil {
			return res, err
		}
		res = append(res, dba.ToAuditRepresentation())
	}

	// Return an error from rows if any error was encountered by Rows.Scan
	return res, rows.Err()
}

// GetEventsSummary gets all available values for Origins, Realms and CtEventTypes
func (cm *eventsDBModule) GetEventsSummary(_ context.Context) (api.EventSummaryRepresentation, error) {
	var res api.EventSummaryRepresentation
	var err error

	// Get realms
	res.Realms, err = cm.queryStringArray(selectAuditSummaryRealmStmt)
	if err == nil {
		// Get origins
		res.Origins, err = cm.queryStringArray(selectAuditSummaryOriginStmt)
	}
	if err == nil {
		// Get ct_event_types
		res.CtEventTypes, err = cm.queryStringArray(selectAuditSummaryCtEventTypeStmt)
	}
	return res, err
}

// GetLastConnection gets the time of last connection for the given realm
func (cm *eventsDBModule) GetLastConnection(_ context.Context, realmName string) (int64, error) {
	var res = int64(0)
	var row = cm.db.QueryRow(selectLastConnectionTimeStmt, realmName)
	var err = row.Scan(&res)
	return res, err
}

// GetTotalConnectionsCount gets the number of connection for the given realm during the specified duration
func (cm *eventsDBModule) GetTotalConnectionsCount(_ context.Context, realmName string, durationLabel string) (int64, error) {
	var matched, err = regexp.MatchString(`^\d+ [A-Za-z]+$`, durationLabel)
	if !matched || err != nil {
		return 0, errors.New(MsgErrInvalidParam + "." + DurationLabel)
	}
	var res = int64(0)
	var row = cm.db.QueryRow(strings.ReplaceAll(selectConnectionsCount, "##INTERVAL##", durationLabel), realmName)
	err = row.Scan(&res)
	return res, err
}

// GetTotalConnectionsHoursCount gets the number of connections for the given realm for the last 24 hours, hour by hour
func (cm *eventsDBModule) GetTotalConnectionsHoursCount(_ context.Context, realmName string) ([][]int64, error) {

	var err error
	var nbHours = 24
	var nbConnections = int64(0)
	var res = make([][]int64, nbHours)
	for i := 0; i < nbHours; i++ {
		res[i] = make([]int64, 2)
		var row = cm.db.QueryRow(strings.ReplaceAll(selectConnectionsHoursCount, "##OFFSET##", strconv.Itoa(i)), realmName)
		err = row.Scan(&nbConnections)
		if time.Now().UTC().Hour()-(i+1) < 0 {
			res[i][0] = int64(24 + (time.Now().UTC().Hour() - i))
		} else {
			res[i][0] = int64((time.Now().UTC().Hour() - i))
		}
		res[i][1] = nbConnections
	}

	return res, err
}

// GetTotalConnectionsHoursCount gets the number of connections for the given realm for the last 30 days, day by day
func (cm *eventsDBModule) GetTotalConnectionsDaysCount(_ context.Context, realmName string) ([][]int64, error) {

	var err error
	var nbDays = 30
	var nbConnections = int64(0)
	var res = make([][]int64, nbDays)

	// we need to know how many days the previous month has
	now := time.Now()
	currentYear, currentMonth, _ := now.Date()
	currentLocation := now.Location()
	firstOfPrevMonth := time.Date(currentYear, currentMonth-1, 1, 0, 0, 0, 0, currentLocation)
	lastOfPrevMonth := firstOfPrevMonth.AddDate(0, 1, -1)
	nbDaysLastMonth := lastOfPrevMonth.Day()
	dayToday := time.Now().UTC().Day()

	for i := 0; i < nbDays; i++ {
		res[i] = make([]int64, 2)
		var row = cm.db.QueryRow(strings.ReplaceAll(selectConnectionsDaysCount, "##OFFSET##", strconv.Itoa(i)), realmName)
		err = row.Scan(&nbConnections)

		if dayToday-(i+1) < 0 {
			res[i][0] = int64(nbDaysLastMonth + (dayToday - i))
		} else {
			res[i][0] = int64(dayToday - i)
		}
		res[i][1] = nbConnections
	}

	return res, err
}

// GetTotalConnectionsHoursCount gets the number of connections for the given realm for the last 24 hours, hour by hour
func (cm *eventsDBModule) GetTotalConnectionsMonthsCount(_ context.Context, realmName string) ([][]int64, error) {

	var err error
	var nbMonths = 12
	var nbConnections = int64(0)
	var res = make([][]int64, nbMonths)
	var currentMonth = int(time.Now().UTC().Month())
	for i := 0; i < nbMonths; i++ {
		res[i] = make([]int64, 2)
		var row = cm.db.QueryRow(strings.ReplaceAll(selectConnectionsMonthsCount, "##OFFSET##", strconv.Itoa(i)), realmName)
		err = row.Scan(&nbConnections)
		if currentMonth-(i+1) < 0 {
			res[i][0] = int64(12 + (currentMonth - i))
		} else {
			res[i][0] = int64(currentMonth - i)
		}
		res[i][1] = nbConnections
	}

	return res, err
}

// GetLastConnections gives information on the last authentications
func (cm *eventsDBModule) GetLastConnections(_ context.Context, realmName string, nbConnections string) ([]api_stat.StatisticsConnectionRepresentation, error) {

	var res = []api_stat.StatisticsConnectionRepresentation{}
	rows, err := cm.db.Query(selectConnectionStmt, realmName, nbConnections)
	if err != nil {
		return res, err
	}
	defer rows.Close()

	for rows.Next() {
		var dbc api_stat.DbConnectionRepresentation
		var addInfos string
		err = rows.Scan(&dbc.Date, &dbc.Result, &dbc.User, &addInfos)
		if err != nil {
			return res, err
		}
		var infos map[string]string
		_ = json.Unmarshal([]byte(addInfos), &infos)
		dbc.IP = string(infos["ip_address"])
		res = append(res, dbc.ToConnRepresentation())
	}

	return res, err
}

func getSQLParam(m map[string]string, name string, defaultValue interface{}) interface{} {
	if value, ok := m[name]; ok {
		return value
	}
	return defaultValue
}

func (cm *eventsDBModule) queryStringArray(request string) ([]string, error) {
	var res []string
	rows, err := cm.db.Query(request)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		rows.Scan(&value)
		res = append(res, value)
	}

	return res, nil
}
