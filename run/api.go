package run

import (
	"encoding/json"
	"reflect"
	"time"
	"unsafe"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rayuruno/ltirun/lti"
)

type Consumer struct {
	Id       string
	Tool     *lti.Registration
	Platform *lti.Platform
}

type Session struct {
	Id       string
	Consumer *Consumer
	Claims   jwt.MapClaims
}

type Store interface {
	Get(key string) ([]byte, error)
	Set(key string, val []byte, exp time.Duration) error
	Delete(key string) error
	Reset() error
	Close() error
}

type KeyStore interface {
	Jwks(id string) ([]byte, error)
	Sign(payload jwt.Claims, id string) (string, error)
	Verify(signed string, jwksUri string) (*jwt.Token, error)
}

type Api struct {
	st Store
	ks KeyStore
}

func New(st Store, ks KeyStore) *Api {
	return &Api{st: st, ks: ks}
}

func hashid(s string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(s)).String()
}

func set[T any](st Store, k string, v T, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return st.Set(k, b, ttl)
}

func get[T any](st Store, k string) (*T, error) {
	b, err := st.Get(k)
	if err != nil {
		return nil, err
	}
	var v T
	err = json.Unmarshal(b, &v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func b2s(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func s2b(s string) (b []byte) {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	bh.Data = sh.Data
	bh.Cap = sh.Len
	bh.Len = sh.Len
	return b
}
