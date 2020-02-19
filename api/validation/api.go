package validation

import (
	"strconv"
	"time"

	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	kc "github.com/cloudtrust/keycloak-client"
)

// UserRepresentation struct
type UserRepresentation struct {
	UserID               *string    `json:"userId,omitempty"`
	Username             *string    `json:"username,omitempty"`
	Gender               *string    `json:"gender,omitempty"`
	FirstName            *string    `json:"firstName,omitempty"`
	LastName             *string    `json:"lastName,omitempty"`
	EmailAddress         *string    `json:"emailAddress,omitempty"`
	EmailAddressVerified *bool      `json:"emailAddressVerified,omitempty"`
	PhoneNumber          *string    `json:"phoneNumber,omitempty"`
	PhoneNumberVerified  *bool      `json:"phoneNumberVerified,omitempty"`
	BirthDate            *time.Time `json:"birthDate,omitempty"`
	BirthLocation        *string    `json:"birthLocation,omitempty"`
	IDDocumentType       *string    `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string    `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *time.Time `json:"idDocumentExpiration,omitempty"`
}

// CheckRepresentation struct
type CheckRepresentation struct {
	UserID    *string    `json:"userId,omitempty"`
	Operator  *string    `json:"operator,omitempty"`
	DateTime  *time.Time `json:"datetime,omitempty"`
	Status    *string    `json:"status,omitempty"`
	Type      *string    `json:"type,omitempty"`
	Nature    *string    `json:"nature,omitempty"`
	ProofData *[]byte    `json:"proofData,omitempty"`
	ProofType *string    `json:"proofType,omitempty"`
}

// Parameter references
const (
	prmUserID                   = "user_id"
	prmUserGender               = "user_gender"
	prmUserFirstName            = "user_firstName"
	prmUserLastName             = "user_lastName"
	prmUserEmail                = "user_emailAddress"
	prmUserPhoneNumber          = "user_phoneNumber"
	prmUserBirthDate            = "user_birthDate"
	prmUserBirthLocation        = "user_birthLocation"
	prmUserIDDocumentType       = "user_idDocType"
	prmUserIDDocumentNumber     = "user_idDocNumber"
	prmUserIDDocumentExpiration = "user_idDocExpiration"

	prmCheckOperator  = "check_operator"
	prmCheckDatetime  = "check_datetime"
	prmCheckStatus    = "check_status"
	prmCheckType      = "check_type"
	prmCheckNature    = "check_nature"
	prmCheckProofType = "check_proof_type"

	RegExpID            = `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`
	regExpNames         = `^([\wàáâäçèéêëìíîïñòóôöùúûüß]+([ '-][\wàáâäçèéêëìíîïñòóôöùúûüß]+)*){1,50}$`
	regExpFirstName     = regExpNames
	regExpLastName      = regExpNames
	regExpEmail         = `^.+\@.+\..+$`
	regExpBirthLocation = regExpNames
	// Multiple values with digits and letters separated by a single separator (space, dash)
	regExpIDDocumentNumber = `^([\w\d]+([ -][\w\d]+)*){1,50}$`

	regExpOperator  = `[a-zA-Z0-9_-]{1,255}`
	regExpNature    = `[a-zA-Z0-9_-]{1,255}`
	regExpProofType = `[a-zA-Z0-9_-]{1,255}`

	DateLayout = "02.01.2006"
)

var (
	allowedGender       = map[string]bool{"M": true, "F": true}
	allowedDocumentType = map[string]bool{"ID_CARD": true, "PASSPORT": true, "RESIDENCE_PERMIT": true}
	allowedCheckType    = map[string]bool{"IDENTITY_CHECK": true}
	allowedStatus       = map[string]bool{
		"SUCCESS":                   true,
		"SUCCESS_DATA_CHANGED":      true,
		"FRAUD_SUSPICION_CONFIRMED": true,
		"REVIEW_PENDING":            true,
		"FRAUD_SUSPICION_PENDING":   true,
	}
)

// ConvertToDBCheck creates a DBCheck
func (c *CheckRepresentation) ConvertToDBCheck() dto.DBCheck {
	var check = dto.DBCheck{}
	check.Operator = c.Operator
	datetime := *c.DateTime
	check.DateTime = &datetime
	check.Status = c.Status
	check.Type = c.Type
	check.Nature = c.Nature
	check.ProofType = c.ProofType
	check.ProofData = c.ProofData

	return check
}

// ExportToKeycloak exports user details into a Keycloak UserRepresentation
func (u *UserRepresentation) ExportToKeycloak(kcUser *kc.UserRepresentation) {
	var bFalse = false
	var bTrue = true
	var attributes = make(map[string][]string)

	if kcUser.Attributes != nil {
		attributes = *kcUser.Attributes
	}

	if u.Gender != nil {
		attributes["gender"] = []string{*u.Gender}
	}
	if u.PhoneNumber != nil {
		if value, ok := attributes["phoneNumber"]; !ok || (len(value) > 0 && value[0] != *u.PhoneNumber) {
			attributes["phoneNumber"] = []string{*u.PhoneNumber}
			attributes["phoneNumberVerified"] = []string{"false"}
		}
	}
	if u.BirthDate != nil {
		var birthDate = *u.BirthDate
		attributes["birthDate"] = []string{birthDate.Format(DateLayout)}
	}

	if u.Username != nil {
		kcUser.Username = u.Username
	}
	if u.EmailAddress != nil && (kcUser.Email == nil || *kcUser.Email != *u.EmailAddress) {
		kcUser.Email = u.EmailAddress
		kcUser.EmailVerified = &bFalse
	}
	if u.FirstName != nil {
		kcUser.FirstName = u.FirstName
	}
	if u.LastName != nil {
		kcUser.LastName = u.LastName
	}
	kcUser.Attributes = &attributes
	kcUser.Enabled = &bTrue
}

// ImportFromKeycloak import details from Keycloak
func (u *UserRepresentation) ImportFromKeycloak(kcUser kc.UserRepresentation) {
	var phoneNumber = u.PhoneNumber
	var phoneNumberVerified = u.PhoneNumberVerified
	var gender = u.Gender
	var birthdate = u.BirthDate

	if kcUser.Attributes != nil {
		var m = *kcUser.Attributes
		if value, ok := m["phoneNumber"]; ok && len(value) > 0 {
			phoneNumber = &value[0]
		}
		if value, ok := m["phoneNumberVerified"]; ok && len(value) > 0 {
			if verified, err := strconv.ParseBool(value[0]); err == nil {
				phoneNumberVerified = &verified
			}
		}
		if value, ok := m["gender"]; ok && len(value) > 0 {
			gender = &value[0]
		}
		if value, ok := m["birthDate"]; ok && len(value) > 0 {
			date, _ := time.Parse(DateLayout, value[0])
			birthdate = &date
		}
	}

	u.UserID = kcUser.Id
	u.Username = kcUser.Username
	u.Gender = gender
	u.FirstName = kcUser.FirstName
	u.LastName = kcUser.LastName
	u.EmailAddress = kcUser.Email
	u.EmailAddressVerified = kcUser.EmailVerified
	u.PhoneNumber = phoneNumber
	u.PhoneNumberVerified = phoneNumberVerified
	u.BirthDate = birthdate
}

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmUserID, u.UserID, RegExpID, false).
		ValidateParameterIn(prmUserGender, u.Gender, allowedGender, false).
		ValidateParameterRegExp(prmUserFirstName, u.FirstName, regExpFirstName, false).
		ValidateParameterRegExp(prmUserLastName, u.LastName, regExpLastName, false).
		ValidateParameterRegExp(prmUserEmail, u.EmailAddress, regExpEmail, false).
		ValidateParameterPhoneNumber(prmUserPhoneNumber, u.PhoneNumber, false).
		ValidateParameterRegExp(prmUserBirthLocation, u.BirthLocation, regExpBirthLocation, false).
		ValidateParameterIn(prmUserIDDocumentType, u.IDDocumentType, allowedDocumentType, false).
		ValidateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, regExpIDDocumentNumber, false).
		Status()
}

// Validate checks the validity of the given check
func (c *CheckRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmUserID, c.UserID, RegExpID, true).
		ValidateParameterRegExp(prmCheckOperator, c.Operator, regExpOperator, true).
		ValidateParameterNotNil(prmCheckDatetime, c.DateTime).
		ValidateParameterIn(prmCheckStatus, c.Status, allowedStatus, true).
		ValidateParameterIn(prmCheckType, c.Type, allowedCheckType, true).
		ValidateParameterRegExp(prmCheckNature, c.Nature, regExpNature, true).
		ValidateParameterRegExp(prmCheckProofType, c.ProofType, regExpProofType, true).
		Status()
}