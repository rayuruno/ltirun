package lti

import (
	"fmt"
	"strings"

	"github.com/rayuruno/ltirun/internal/check"
)

// https://www.imsglobal.org/spec/lti-dr/v1p0#platform-configuration
type Platform struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint,omitempty"`
	JwksUri                                    string   `json:"jwks_uri"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	IdTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IdTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported       []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported       []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                     []string `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                        []string `json:"claim_types_supported,omitempty"`
	ClaimsSupported                            []string `json:"claims_supported,omitempty"`
	ServiceDocumentation                       string   `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                     []string `json:"claims_locales_supported,omitempty"`
	UiLocalesSupported                         []string `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported,omitempty"`
	RequestUriParameterSupported               bool     `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestUriRegistration              bool     `json:"require_request_uri_registration,omitempty"`
	OpPolicyUri                                string   `json:"op_policy_uri,omitempty"`
	OpTosUri                                   string   `json:"op_tos_uri,omitempty"`
	LtiPlatform                                `json:"https://purl.imsglobal.org/spec/lti-platform-configuration"`
}

func (c *Platform) Validate(drUrl string) error {
	if !check.ContainsAll(c.TokenEndpointAuthMethodsSupported, "private_key_jwt") {
		return fmt.Errorf("token_endpoint_auth_methods_supported must contain private_key_jwt")
	}
	if !check.ContainsAll(c.TokenEndpointAuthSigningAlgValuesSupported, "RS256") {
		return fmt.Errorf("token_endpoint_auth_signing_alg_values_supported must contain RS256")
	}
	if !check.ContainsAll(c.ScopesSupported, "openid") {
		return fmt.Errorf("scopes_supported must contain openid")
	}
	if !check.ContainsAll(c.ResponseTypesSupported, "id_token") {
		return fmt.Errorf("response_types_supported must contain id_token")
	}
	if !check.ContainsAll(c.IdTokenSigningAlgValuesSupported, "RS256") {
		return fmt.Errorf("id_token_signing_alg_values_supported must contain RS256")
	}
	// dynamic only
	if drUrl != "" && !strings.HasPrefix(drUrl, c.Issuer) {
		return fmt.Errorf("invalid platform")
	}
	return nil
}

// https://www.imsglobal.org/spec/lti-dr/v1p0#lti-configuration
type LtiPlatform struct {
	ProductFamilyCode string             `json:"product_family_code"`
	Version           string             `json:"version"`
	MessagesSupported []MessageSupported `json:"messages_supported"`
	Variables         []string           `json:"variables,omitempty"`
}

type MessageSupported struct {
	Type       string   `json:"type"`
	Placements []string `json:"placements,omitempty"`
}
