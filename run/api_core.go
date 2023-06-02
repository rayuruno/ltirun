package run

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-querystring/query"
	"github.com/google/uuid"
	"github.com/rayuruno/ltirun/lti"
)

func (api *Api) Authn(providerUri string, i *lti.LoginInit) (string, error) {
	c, err := get[Consumer](api.st, consumerId(providerUri, i))
	if err != nil {
		return "", err
	}

	targetLinkUrl, err := url.Parse(i.TargetLinkUri)
	if err != nil {
		return "", err
	}
	if c.Tool.Domain != targetLinkUrl.Hostname() {
		return "", fmt.Errorf("domain mismatch %s != %s", c.Tool.Domain, targetLinkUrl.Hostname())
	}

	state := hashid(i.LoginHint)
	nonce := hashid(state)

	err = set(api.st, state, i, time.Minute*1)
	if err != nil {
		return "", err
	}

	ar := &lti.AuthenticateRequest{
		Scope:          "openid",
		ResponseType:   "id_token",
		ClientId:       i.ClientId,
		RedirectUri:    i.TargetLinkUri,
		LoginHint:      i.LoginHint,
		LtiMessageHint: i.LtiMessageHint,
		State:          state,
		ResponseMode:   "form_post",
		Nonce:          nonce,
		Prompt:         "none",
	}
	av, err := query.Values(ar)
	if err != nil {
		return "", err
	}
	return c.Platform.AuthorizationEndpoint + "?" + av.Encode(), nil
}
func (api *Api) Authz(providerUri string, a *lti.AuthenticateResponse) (*Session, error) {
	i, err := get[lti.LoginInit](api.st, a.State)
	if err != nil {
		return nil, err
	}
	if hashid(i.LoginHint) != a.State {
		return nil, fmt.Errorf("invalid state")
	}
	c, err := get[Consumer](api.st, consumerId(providerUri, i))
	if err != nil {
		return nil, err
	}
	token, err := api.ks.Verify(a.IdToken, c.Platform.JwksUri)
	if err != nil {
		return nil, err
	}
	s := &Session{Id: uuid.NewString(), Consumer: c, Claims: token.Claims.(jwt.MapClaims)}
	exp, err := token.Claims.GetExpirationTime()
	if err != nil {
		return nil, err
	}
	err = set(api.st, s.Id, s, exp.Sub(time.Now()))
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (api *Api) Launch(s *Session, b *string) error {
	uri, err := targetLinkUriFromToken(s.Claims)
	if err != nil {
		return err
	}
	token, err := api.ks.Sign(jwt.RegisteredClaims{
		Issuer:    s.Consumer.Tool.Domain,
		Subject:   s.Id,
		Audience:  jwt.ClaimStrings{uri},
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour * 2)),
		ID:        hashid(s.Id),
	}, s.Consumer.Id)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
	defer cancel()

	return requests.
		URL(uri).
		Method(http.MethodPost).
		Bearer(token).
		BodyJSON(s.Claims).
		ContentType("text/html").
		ToString(b).
		Fetch(ctx)
}

func consumerId(providerUri string, i *lti.LoginInit) string {
	return providerUri + " " + i.Iss + " " + i.ClientId + " " + i.DeploymentId
}
func targetLinkUriFromToken(claims jwt.MapClaims) (string, error) {
	mtype, ok := claims["https://purl.imsglobal.org/spec/lti/claim/message_type"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token")
	}
	custom, ok := claims["https://purl.imsglobal.org/spec/lti/claim/custom"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("invalid token")
	}
	uri, ok := custom[mtype].(string)
	if !ok {
		return "", fmt.Errorf("invalid token")
	}
	return uri, nil
}
