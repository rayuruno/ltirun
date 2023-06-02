package keystore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base32"
	"strings"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

type keyStore struct {
	ctx context.Context
	set jwkset.JWKSet[any]
}

func New() *keyStore {
	return &keyStore{
		set: jwkset.NewMemory[any](),
		ctx: context.Background(),
	}
}
func (s *keyStore) Jwks(id string) ([]byte, error) {
	return s.set.JSONPublic(s.ctx)
}
func (s *keyStore) Sign(claims jwt.Claims, id string) (string, error) {
	signingKey, err := s.signingKey(id)
	if err != nil {
		return "", err
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = signingKey.KeyID
	t.Header["alg"] = signingKey.ALG.String()
	return t.SignedString(signingKey.Key)
}
func (s *keyStore) signingKey(id string) (*jwkset.KeyWithMeta[any], error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	kid, err := publicKeyId(key)
	if err != nil {
		return nil, err
	}
	pkey := jwkset.NewKey[any](key, kid)
	pkey.ALG = "RS256"
	err = s.set.Store.WriteKey(s.ctx, pkey)
	if err != nil {
		return nil, err
	}
	return &pkey, nil
}
func (*keyStore) Verify(signed string, jwksUri string) (*jwt.Token, error) {
	jwks, err := keyfunc.Get(jwksUri, keyfunc.Options{})
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(signed, jwks.Keyfunc, jwt.WithTimeFunc(func() time.Time {
		return time.Now().UTC().Add(time.Second * 20)
	}))
	if err != nil {
		return nil, err
	}
	return token, nil
}
func publicKeyId(key *rsa.PrivateKey) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	hasher := crypto.SHA256.New()
	hasher.Write(b)
	return encodeKeyId(hasher.Sum(nil)[:30]), nil
}
func encodeKeyId(b []byte) string {
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
	var buf bytes.Buffer
	var i int
	for i = 0; i < len(s)/4-1; i++ {
		start := i * 4
		end := start + 4
		buf.WriteString(s[start:end] + ":")
	}
	buf.WriteString(s[i*4:])
	return buf.String()
}
