package lti

import (
	"encoding/json"

	"github.com/google/go-querystring/query"
)

// https://imsglobal.org/spec/security/v1p0/#platform-originating-messages
type LoginInit struct {
	Iss            string `form:"iss" query:"iss"`
	LoginHint      string `form:"login_hint" query:"login_hint"`
	TargetLinkUri  string `form:"target_link_uri" query:"target_link_uri"`
	LtiMessageHint string `form:"lti_message_hint" query:"lti_message_hint"`
	ClientId       string `form:"client_id" query:"client_id"`
	DeploymentId   string `form:"lti_deployment_id" query:"lti_deployment_id"` //bug, with or without lti?
}

// https://imsglobal.org/spec/security/v1p0/#step-2-authentication-request
type AuthenticateRequest struct {
	Scope          string `url:"scope"`
	ResponseType   string `url:"response_type"`
	ClientId       string `url:"client_id"`
	RedirectUri    string `url:"redirect_uri"`
	LoginHint      string `url:"login_hint"`
	LtiMessageHint string `url:"lti_message_hint"`
	State          string `url:"state"`
	ResponseMode   string `url:"response_mode"`
	Nonce          string `url:"nonce"`
	Prompt         string `url:"prompt"`
}

func (a *AuthenticateRequest) Encode() (string, error) {
	q, err := query.Values(a)
	if err != nil {
		return "", err
	}
	return q.Encode(), nil
}

// https://imsglobal.org/spec/security/v1p0/#step-3-authentication-response
type AuthenticateResponse struct {
	State   string `form:"state" query:"state"`
	IdToken string `form:"id_token" query:"id_token"`
}

type AccessToken struct {
	Token     string `json:"access_token"`
	Type      string `json:"token_type"`
	ExpiresIn any    `json:"expires_in"`
	Scope     string `json:"scope"`
}

type ServiceRequest struct {
	Scope       string          `json:"scope"`
	Method      string          `json:"method"`
	ContentType string          `json:"content_type"`
	Accept      string          `json:"accept"`
	Endpoint    string          `json:"endpoint"`
	Body        json.RawMessage `json:"body"`
}
