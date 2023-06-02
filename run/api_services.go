package run

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rayuruno/ltirun/lti"
	"github.com/rs/zerolog/log"
)

func (api *Api) JsonWebKeys(providerUri string) ([]byte, error) {
	return api.ks.Jwks(providerUri)
}
func (api *Api) GetSession(jwksUri, signed string) (*Session, error) {
	token, err := api.ks.Verify(signed, jwksUri)
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(jwt.MapClaims)
	log.Debug().Any("claims", claims).Msg("GetSession")
	s, err := get[Session](api.st, claims["sub"].(string))
	if err != nil {
		return nil, err
	}
	if hashid(s.Id) != claims["jti"].(string) {
		return nil, fmt.Errorf("Unauthorized")
	}
	return s, nil
}
func (api *Api) GetAccessToken(s *Session, r *lti.ServiceRequest, t *lti.AccessToken) error {
	sig, err := api.ks.Sign(jwt.RegisteredClaims{
		Issuer:    s.Consumer.Tool.Domain,
		Subject:   s.Consumer.Tool.ClientId,
		Audience:  jwt.ClaimStrings{s.Consumer.Platform.TokenEndpoint},
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour * 1)),
		ID:        hashid(s.Id),
	}, s.Consumer.Id)
	if err != nil {
		return err
	}

	v := make(url.Values)
	v.Set("grant_type", "client_credentials")
	v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	v.Set("client_assertion", sig)
	v.Set("scope", r.Scope)

	res, err := http.PostForm(s.Consumer.Platform.TokenEndpoint, v)
	if err != nil {
		return err
	}
	if res.StatusCode >= 400 {
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		return fmt.Errorf("token request failed %s %s %s", res.Status, b, err)
	}

	return json.NewDecoder(res.Body).Decode(t)
}
func (api *Api) SendServiceRequest(a *lti.AccessToken, r *lti.ServiceRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
	defer cancel()

	return requests.
		URL(r.Endpoint).
		Method(r.Method).
		Bearer(a.Token).
		ContentType(r.ContentType).
		Accept(r.Accept).
		BodyBytes(r.Body).
		Fetch(ctx)
}
func (api *Api) SignJWT(s *Session, p []byte) (string, error) {
	claims := make(jwt.MapClaims)
	err := json.Unmarshal(p, &claims)
	if err != nil {
		return "", nil
	}
	return api.ks.Sign(claims, s.Consumer.Id)
}
