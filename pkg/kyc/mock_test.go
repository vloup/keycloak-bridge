package kyc

//go:generate mockgen -destination=./mock/kyc.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,EventsDBModule=EventsDBModule,UsersDetailsDBModule=UsersDetailsDBModule github.com/cloudtrust/keycloak-bridge/pkg/kyc Component,KeycloakClient,EventsDBModule,UsersDetailsDBModule
//go:generate mockgen -destination=./mock/sqltypes.go -package=mock -mock_names=SQLRow=SQLRow,Transaction=Transaction github.com/cloudtrust/common-service/database/sqltypes SQLRow,Transaction
//go:generate mockgen -destination=./mock/security.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/security AuthorizationManager
//go:generate mockgen -destination=./mock/middleware.go -package=mock -mock_names=EndpointAvailabilityChecker=EndpointAvailabilityChecker github.com/cloudtrust/common-service/middleware EndpointAvailabilityChecker
//go:generate mockgen -destination=./mock/internal.go -package=mock -mock_names=AccreditationsModule=AccreditationsModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb AccreditationsModule
//go:generate mockgen -destination=./mock/keycloak.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/toolbox OidcTokenProvider
