package token

import (
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
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
	refreshExp   time.Duration
}

type OptProvider func(*Provider)

// Initialze the Provider configuration used to generate tokens.
// If not specified in parameters it uses the following configuration by default :
// - temporality : time.Now()
// - signedMethod : HS256
// - accessExp : 5 minutes
// - refreshExp : 30 days
func NewProvider(key string, opts ...OptProvider) *Provider {
	cfg := &Provider{
		temporality:  currentUTC,
		signedKey:    []byte(key),
		signedMethod: jwt.SigningMethodHS256,
		accessExp:    time.Minute * 5,
		refreshExp:   time.Hour * 720,
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

func RefreshExpIn(d time.Duration) OptProvider {
	return func(cfg *Provider) {
		cfg.refreshExp = d
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

// Creates a Token (Acces + Refresh)
func (p *Provider) New(c Claims) (*Token, error) {
	// create token holding properties
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	// the raw token (string)
	at, err := t.SignedString(p.signedKey)
	if err != nil {
		return nil, err
	}
	token := &Token{
		Access:  at,
		Refresh: newRefreshTokenString(),
		Claims:  c,
	}
	return token, nil
}

// Returns the claims associated with the given access token
func (p *Provider) Parse(at string, claims Claims) error {
	// set the time provider in order to enable testing the expiry date
	jwt.TimeFunc = p.temporality
	_, err := jwt.ParseWithClaims(at, claims, func(t *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errInvalidSigningMethod
		}
		// []byte containing secret key, e.g. []byte("my_secret_key")
		return []byte(p.signedKey), nil
	})
	if err != nil {
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
		return err
	}
	return nil
}

func (p *Provider) Refresh(rt string) (*Token, error) {
	// 1. retrieve the claims stored in Redis from the Refresh Token
	claims, err := getClaims(rt)
	if err != nil {
		return nil, err
	}
	// 2. generate a new access token & new refresh token
	token, err := p.New(claims)
	if err != nil {
		return nil, err
	}
	// rt := newRefreshTokenString() <- should be call from provider.New()
	// 3. update Redis
	return token, nil
}

// Returns Claims associated with the given Refresh Token
func getClaims(rt string) (Claims, error) {
	return &AccessClaims{}, nil
}

func newRefreshTokenString() string {
	s := uuid.New().String()
	code := base64.URLEncoding.EncodeToString([]byte(s))
	code = strings.Trim(code, "=")
	return code
}
