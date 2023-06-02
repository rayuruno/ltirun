package lti

// https://www.imsglobal.org/spec/lti-dr/v1p0#step-1-registration-initiation-request
type RegistrationInit struct {
	Endpoint string `query:"openid_configuration" form:"openid_configuration"`
	Token    string `query:"registration_token" form:"registration_token"`
}

// https://www.imsglobal.org/spec/lti-dr/v1p0#tool-configuration-from-the-platform
type Registration struct {
	*Tool
	ClientId              string `json:"client_id"`
	RegistrationClientUri string `json:"registration_client_uri,omitempty"`
}
