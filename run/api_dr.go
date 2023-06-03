package run

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/rayuruno/ltirun/lti"
)

func (api *Api) GetPlatformConfig(endpoint, token string, p *lti.Platform) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
	defer cancel()
	return requests.
		URL(endpoint).
		Method(http.MethodGet).
		Bearer(token).
		ToJSON(p).
		Fetch(ctx)
}
func (api *Api) LoadToolConfig(serviceUrl, providerUri string, t *lti.Tool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
	defer cancel()
	requests.
		URL("https://" + providerUri + "/.well-known/openid_configuration").
		Method(http.MethodGet).
		ToJSON(t).
		Fetch(ctx)
	return proxyToolConfig(serviceUrl, providerUri, t)
}
func (api *Api) PostToolConfig(registrationEndpoint, token string, t *lti.Tool, r *lti.Registration) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
	defer cancel()
	return requests.
		URL(registrationEndpoint).
		Method(http.MethodPost).
		Bearer(token).
		BodyJSON(t).
		ToJSON(r).
		Fetch(ctx)
}
func (api *Api) StoreRegistration(providerUri string, p *lti.Platform, r *lti.Registration) error {
	c := &Consumer{
		Id:       providerUri + " " + p.Issuer + " " + r.ClientId + " " + r.DeploymentId,
		Tool:     r,
		Platform: p,
	}
	return set(api.st, c.Id, c, 0)
}

func proxyToolConfig(serviceUrl, providerUri string, t *lti.Tool) error {
	if t == nil {
		t = new(lti.Tool)
	}
	srvUrl, err := url.Parse(serviceUrl)
	if err != nil {
		return err
	}
	provUrl, err := url.Parse("https://" + providerUri)
	if err != nil {
		return err
	}
	if !strings.Contains(provUrl.Hostname(), ".") {
		return fmt.Errorf("invalid provider uri %s, host missing", providerUri)
	}
	jwksUri := srvUrl.JoinPath("jwks").String() + "/" + providerUri
	initiateLoginUri := srvUrl.JoinPath("login").String() + "/" + providerUri
	targetLinkUri := srvUrl.JoinPath("launch").String() + "/" + providerUri

	if t.TargetLinkUri != "" {
		providerTargetLinkUrl, err := url.Parse(t.TargetLinkUri)
		if err != nil {
			return err
		}
		if provUrl.Hostname() != providerTargetLinkUrl.Hostname() {
			return fmt.Errorf("host mismatch %s %s", providerUri, providerTargetLinkUrl)
		}
	}
	t.ApplicationType = "web"
	t.ResponseTypes = []string{"id_token"}
	t.GrantTypes = []string{"client_credentials", "implicit"}
	t.RedirectUris = []string{initiateLoginUri, targetLinkUri}
	t.JwksUri = jwksUri
	t.InitiateLoginUri = initiateLoginUri
	t.TokenEndpointAuthMethod = "private_key_jwt"
	t.IdTokenSignedResponseAlg = "RS256"
	t.Domain = srvUrl.Hostname()
	t.TargetLinkUri = targetLinkUri
	if t.ClientName == "" {
		t.ClientName = provUrl.Hostname()
	}
	if t.ClientUri == "" {
		t.ClientUri = provUrl.String()
	}
	if len(t.Messages) == 0 {
		t.Messages = defaultMessages()
	} else {
		for i, m := range t.Messages {
			if m.TargetLinkUri != "" {
				mTargetLinkUrl, err := url.Parse(m.TargetLinkUri)
				if err != nil {
					return err
				}
				if provUrl.Hostname() != mTargetLinkUrl.Hostname() {
					return fmt.Errorf("host mismatch %s %s", providerUri, mTargetLinkUrl)
				}
			}
			t.Messages[i].TargetLinkUri = targetLinkUri
		}
	}
	t.Scope = defaultScope
	if len(t.Claims) == 0 {
		t.Claims = defaultClaims
	}
	return nil
}

var defaultScope = strings.Join([]string{
	"openid",
	"https://purl.imsglobal.org/spec/lti-reg/scope/registration.readonly",
	"https://purl.imsglobal.org/spec/lti-reg/scope/registration",
	"https://purl.imsglobal.org/spec/lti-gs/scope/contextgroup.readonly",
	"https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
	"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
	"https://purl.imsglobal.org/spec/lti-ags/scope/result",
	"https://purl.imsglobal.org/spec/lti-ags/scope/score",
	"https://purl.imsglobal.org/spec/lti-ts/scope/toolsetting",
}, " ")

var defaultClaims = []string{
	"iss",
	"sub",
	"aud",
	"name",
	"email",
	"locale",
}

func defaultMessages() []lti.LtiMessage {
	return []lti.LtiMessage{
		{
			Type:  "LtiResourceLinkRequest",
			Label: "Global Settings",
			Roles: []string{
				"https://purl.imsglobal.org/vocab/lis/v2/membership#Administrator",
			},
		},
		{
			Type:  "LtiDeepLinkingRequest",
			Label: "Settings",
			Roles: []string{
				"https://purl.imsglobal.org/vocab/lis/v2/membership#Administrator",
				"https://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
			},
		},
		{
			Type:  "LtiResourceLinkRequest",
			Label: "Launch",
			Roles: []string{
				"https://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
				"https://purl.imsglobal.org/vocab/lis/v2/membership#Student",
			},
		},
		{
			Type:  "LtiStartProctoring",
			Label: "Launch",
			Roles: []string{
				"https://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
				"https://purl.imsglobal.org/vocab/lis/v2/membership#Student",
			},
		},
	}
}
