package token

import (
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

var (
	currentUTC = func() time.Time {
		return time.Now().UTC()
	}
)

// Token Provider type that handles the creation/refresh of token
type Provider struct {
	temporality  func() time.Time
	signedKey    []byte
	signedMethod jwt.SigningMethod
	accessExp    time.Duration
	store        Store
}

type OptProvider func(*Provider)

// Initialze the Provider configuration used to generate tokens.
// If not specified in parameters it uses the following configuration by default :
// - temporality : time.Now()
// - signedMethod : HS256
// - accessExp : 5 minutes
func NewProvider(key string, store Store, opts ...OptProvider) *Provider {
	cfg := &Provider{
		temporality:  currentUTC,
		signedKey:    []byte(key),
		signedMethod: jwt.SigningMethodHS256,
		accessExp:    time.Minute * 5,
		store:        store,
	}
	for _, v := range opts {
		v(cfg)
	}
	return cfg
}

func AccessExpIn(d time.Duration) OptProvider {
	return func(cfg *Provider) {
		cfg.accessExp = d
	}
}

func Alg(s string) OptProvider {
	return func(cfg *Provider) {
		cfg.signedMethod = jwt.GetSigningMethod(s)
	}
}

func TimeFunc(f func() time.Time) OptProvider {
	return func(cfg *Provider) {
		cfg.temporality = f
	}
}

// Creates a Token (Acces & Refresh)
func (p *Provider) New(c *AccessClaims) (*Token, error) {
	// the access token
	at, err := p.newAccessToken(c)
	if err != nil {
		return nil, err
	}

	// the refresh token
	rt, err := p.newRefreshToken(c)
	if err != nil {
		return nil, err
	}

	// the whole token entity
	token := &Token{
		Access:  at,
		Refresh: rt,
		Claims:  c,
	}
	log.Info("New Token (at & rt) generated successfully")
	return token, nil
}

// Returns the claims associated with the given access token
func (p *Provider) Parse(at string, cl *AccessClaims) error {
	// set the time provider in order to enable testing the expiry date
	jwt.TimeFunc = p.temporality
	_, err := jwt.ParseWithClaims(at, cl, func(t *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errInvalidSigningMethod
		}
		// []byte containing secret key, e.g. []byte("my_secret_key")
		return []byte(p.signedKey), nil
	})
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

// Returns whether or not the given access token is valid
func (p *Provider) Validate(at string) error {
	// set the time provider in order to enable testing the expiry date
	jwt.TimeFunc = p.temporality
	_, err := jwt.Parse(at, func(t *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errInvalidSigningMethod
		}
		// []byte containing secret key, e.g. []byte("my_secret_key")
		return []byte(p.signedKey), nil
	})
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (p *Provider) Refresh(rt string) (*Token, error) {
	// retrieve the claims stored in Redis from the Refresh Token
	cl, err := p.store.Get(rt)
	if err != nil {
		return nil, err
	}

	// update the claims
	cl.ExpiresAt = p.temporality().Add(p.accessExp).UTC().Unix()
	cl.IssuedAt = p.temporality().UTC().Unix()

	// revoke former Refresh Token
	err = p.revokeRefreshToken(rt)
	if err != nil {
		return nil, err
	}

	// generate a new Token (access & refresh)
	token, err := p.New(cl)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// Returns Claims associated with the given Refresh Token
func getClaims(rt string) (*AccessClaims, error) {
	return &AccessClaims{}, nil
}

func (p Provider) newAccessToken(c *AccessClaims) (string, error) {
	// create token holding properties
	t := jwt.NewWithClaims(p.signedMethod, c)

	// the access token
	at, err := t.SignedString(p.signedKey)
	if err != nil {
		log.Error(err)
		return "", err
	}
	return at, nil
}

func (p Provider) newRefreshToken(c *AccessClaims) (string, error) {
	// generate random uuid
	s := uuid.New().String()
	rt := base64.URLEncoding.EncodeToString([]byte(s))
	rt = strings.Trim(rt, "=")

	err := p.store.Set(rt, c)
	if err != nil {
		log.Error(err)
		return "", err
	}
	return rt, nil
}

func (p Provider) revokeRefreshToken(rt string) error {
	_, err := p.store.Del(rt)
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}
