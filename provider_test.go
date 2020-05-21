package token

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type JWTClaims struct {
	jwt.StandardClaims
}

func TestNewProvider(t *testing.T) {
	timeStub := func() time.Time {
		return time.Date(2020, time.March, 5, 0, 0, 0, 0, time.UTC)
	}
	table := []struct {
		key    string
		opts   []OptProvider
		config Provider
	}{
		{
			"shannon",
			[]OptProvider{
				func(cfg *Provider) { cfg.temporality = timeStub },
			},
			Provider{
				temporality:  timeStub,
				signedKey:    []byte("shannon"),
				signedMethod: jwt.SigningMethodHS256,
				accessExp:    time.Minute * 5,
				refreshExp:   time.Hour * 720, // 30 days
			},
		},
		{
			"shannon",
			[]OptProvider{
				func(cfg *Provider) { cfg.temporality = timeStub },
				Alg("HS512"),
			},
			Provider{
				temporality:  timeStub,
				signedKey:    []byte("shannon"),
				signedMethod: jwt.SigningMethodHS512,
				accessExp:    time.Minute * 5,
				refreshExp:   time.Hour * 720, // 30 days
			},
		},
		{
			"shannon",
			[]OptProvider{
				func(cfg *Provider) { cfg.temporality = timeStub },
				Alg("HS512"),
				AccessExpIn(time.Minute * 53),
				RefreshExpIn(time.Hour * 240),
			},
			Provider{
				temporality:  timeStub,
				signedKey:    []byte("shannon"),
				signedMethod: jwt.SigningMethodHS512,
				accessExp:    time.Minute * 53,
				refreshExp:   time.Hour * 240, // 10 days
			},
		},
	}
	for _, v := range table {
		cfg := NewProvider(v.key, v.opts...)
		assert.Equal(t, v.config.accessExp, cfg.accessExp)
		assert.Equal(t, v.config.refreshExp, cfg.refreshExp)
		assert.Equal(t, v.config.signedKey, cfg.signedKey)
		assert.Equal(t, v.config.signedMethod, cfg.signedMethod)
		assert.Equal(t, v.config.temporality(), cfg.temporality())
	}
}

func TestNewToken(t *testing.T) {
	timeStub := func() time.Time {
		return time.Date(2020, time.March, 5, 0, 0, 0, 0, time.UTC)
	}
	svc := NewProvider("shannon")
	table := []struct {
		claims Claims
		access string
	}{
		{
			&JWTClaims{
				jwt.StandardClaims{
					Audience:  "App1",
					Subject:   "Taylor",
					ExpiresAt: timeStub().Add(time.Minute * 5).Unix(),
					IssuedAt:  timeStub().Unix(),
				},
			},
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJBcHAxIiwiZXhwIjoxNTgzMzY2NzAwLCJpYXQiOjE1ODMzNjY0MDAsInN1YiI6IlRheWxvciJ9.bmmYJDx5GvGq10H0xIMW01aTOM1T7BztTZ_DxRWfHgE",
		},
	}
	for _, v := range table {
		token, _ := svc.New(v.claims)
		if token != nil {
			assert.Equal(t, v.access, token.Access)
			assert.Equal(t, v.claims, token.Claims)
		} else {
			assert.Nil(t, token)
		}
	}
}

func TestParseToken(t *testing.T) {
	timeStub := func() time.Time {
		return time.Date(2020, time.March, 5, 0, 0, 0, 0, time.UTC)
	}
	svc := NewProvider("shannon", func(c *Provider) { c.temporality = timeStub })
	table := []struct {
		token  string
		claims *JWTClaims
	}{
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJBcHAxIiwiZXhwIjoxNTgzMzY2NzAwLCJpYXQiOjE1ODMzNjY0MDAsInN1YiI6IlRheWxvciJ9.bmmYJDx5GvGq10H0xIMW01aTOM1T7BztTZ_DxRWfHgE",
			&JWTClaims{
				jwt.StandardClaims{
					Audience:  "App1",
					Subject:   "Taylor",
					ExpiresAt: timeStub().Add(time.Minute * 5).Unix(),
					IssuedAt:  timeStub().Unix(),
				},
			},
		},
	}
	for _, v := range table {
		var claims = &JWTClaims{}
		err := svc.Parse(v.token, claims)
		assert.NoError(t, err)
		assert.Equal(t, v.claims.Audience, claims.Audience)
		assert.Equal(t, v.claims.Subject, claims.Subject)
		assert.Equal(t, v.claims.ExpiresAt, claims.ExpiresAt)
		assert.Equal(t, v.claims.IssuedAt, claims.IssuedAt)
	}
}

func TestValidateToken(t *testing.T) {
	timeStub := func() time.Time {
		return time.Date(2020, time.March, 5, 0, 0, 0, 0, time.UTC)
	}
	svc := NewProvider("shannon", func(c *Provider) { c.temporality = timeStub })
	table := []struct {
		token string
	}{
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJBcHAxIiwiZXhwIjoxNTgzMzY2NzAwLCJpYXQiOjE1ODMzNjY0MDAsInN1YiI6IlRheWxvciJ9.bmmYJDx5GvGq10H0xIMW01aTOM1T7BztTZ_DxRWfHgE",
		},
	}
	for _, v := range table {
		err := svc.Validate(v.token)
		assert.NoError(t, err)
	}
}
