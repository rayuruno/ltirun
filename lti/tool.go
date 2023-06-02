package lti

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rayuruno/ltirun/internal/check"
)

// https://www.imsglobal.org/spec/lti-dr/v1p0#tool-configuration
type Tool struct {
	RedirectUris                 []string        `json:"redirect_uris"`
	ResponseTypes                []string        `json:"response_types,omitempty"`
	GrantTypes                   []string        `json:"grant_types,omitempty"`
	ApplicationType              string          `json:"application_type,omitempty"`
	Contacts                     []string        `json:"contacts,omitempty"`
	ClientName                   string          `json:"client_name,omitempty"`
	LogoUri                      string          `json:"logo_uri,omitempty"`
	ClientUri                    string          `json:"client_uri,omitempty"`
	PolicyUri                    string          `json:"policy_uri,omitempty"`
	TosUri                       string          `json:"tos_uri,omitempty"`
	JwksUri                      string          `json:"jwks_uri,omitempty"`
	Jwks                         json.RawMessage `json:"jwks,omitempty"`
	SectorIdentifierUri          string          `json:"sector_identifier_uri,omitempty"`
	SubjectType                  string          `json:"subject_type,omitempty"`
	IdTokenSignedResponseAlg     string          `json:"id_token_signed_response_alg,omitempty"`
	IdTokenEncryptedResponseAlg  string          `json:"id_token_encrypted_response_alg,omitempty"`
	IdTokenEncryptedResponseEnc  string          `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoSignedResponseAlg    string          `json:"userinfo_signed_response_alg,omitempty"`
	UserinfoEncryptedResponseAlg string          `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc string          `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestObjectSigningAlg      string          `json:"request_object_signing_alg,omitempty"`
	RequestObjectEncryptionAlg   string          `json:"request_object_encryption_alg,omitempty"`
	RequestObjectEncryptionEnc   string          `json:"request_object_encryption_enc,omitempty"`
	TokenEndpointAuthMethod      string          `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg  string          `json:"token_endpoint_auth_signing_alg,omitempty"`
	DefaultMaxAge                int             `json:"default_max_age,omitempty"`
	RequireAuthTime              bool            `json:"require_auth_time,omitempty"`
	DefaultAcrValues             []string        `json:"default_acr_values,omitempty"`
	InitiateLoginUri             string          `json:"initiate_login_uri,omitempty"`
	RequestUris                  []string        `json:"request_uris,omitempty"`
	Scope                        string          `json:"scope"`
	LtiTool                      `json:"https://purl.imsglobal.org/spec/lti-tool-configuration"`
}

func (c *Tool) Validate() error {
	if c.ApplicationType != "web" {
		return fmt.Errorf("application_type must be web")
	}
	if !check.ContainsAll(c.GrantTypes, "client_credentials", "implicit") {
		return fmt.Errorf("grant_types must contain client_credentials")
	}
	if !strings.Contains(c.Scope, "openid") {
		return fmt.Errorf("scopes must contain openid")
	}
	if !check.ContainsAll(c.ResponseTypes, "id_token") {
		return fmt.Errorf("response_types_ must contain id_token")
	}
	if c.TokenEndpointAuthMethod != "private_key_jwt" {
		return fmt.Errorf("token_endpoint_auth_method must be private_key_jwt")
	}
	return nil
}

// https://www.imsglobal.org/spec/lti-dr/v1p0#lti-configuration-0
type LtiTool struct {
	Domain           string         `json:"domain"`
	SecondaryDomains []string       `json:"secondary_domains,omitempty"`
	DeploymentId     string         `json:"deployment_id,omitempty"`
	TargetLinkUri    string         `json:"target_link_uri"`
	CustomParameters map[string]any `json:"custom_parameters,omitempty"`
	Description      string         `json:"description,omitempty"`
	Messages         []LtiMessage   `json:"messages"`
	Claims           []string       `json:"claims"`
}

// https://www.imsglobal.org/spec/lti-dr/v1p0#lti-message
type LtiMessage struct {
	Type             string         `json:"type"`
	TargetLinkUri    string         `json:"target_link_uri,omitempty"`
	Label            string         `json:"label,omitempty"`
	IconUri          string         `json:"icon_uri,omitempty"`
	CustomParameters map[string]any `json:"custom_parameters,omitempty"`
	Placements       []string       `json:"placements,omitempty"`
	Roles            []string       `json:"roles,omitempty"`
}
