package token

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type mockStore struct{}

func (s *mockStore) Get(rt string) (*AccessClaims, error) {
	return &AccessClaims{}, nil
}

func (s *mockStore) Set(rt string, cl *AccessClaims) error {
	return nil
}

func (s *mockStore) Del(rt string) (int64, error) {
	return 1, nil
}

func TestNewProvider(t *testing.T) {
	timeStub := func() time.Time {
		return time.Date(2020, time.March, 5, 0, 0, 0, 0, time.UTC)
	}
	store := &mockStore{}
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
			},
		},
		{
			"shannon",
			[]OptProvider{
				func(cfg *Provider) { cfg.temporality = timeStub },
				Alg("HS512"),
				AccessExpIn(time.Minute * 53),
			},
			Provider{
				temporality:  timeStub,
				signedKey:    []byte("shannon"),
				signedMethod: jwt.SigningMethodHS512,
				accessExp:    time.Minute * 53,
			},
		},
	}
	for _, v := range table {
		cfg := NewProvider(v.key, store, v.opts...)
		assert.Equal(t, v.config.accessExp, cfg.accessExp)
		assert.Equal(t, v.config.signedKey, cfg.signedKey)
		assert.Equal(t, v.config.signedMethod, cfg.signedMethod)
		assert.Equal(t, v.config.temporality(), cfg.temporality())
	}
}

func TestNewToken(t *testing.T) {
	timeStub := func() time.Time {
		return time.Date(2020, time.March, 5, 0, 0, 0, 0, time.UTC)
	}
	store := &mockStore{}
	svc := NewProvider("shannon", store)
	table := []struct {
		claims *AccessClaims
		access string
	}{
		{
			&AccessClaims{
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
	store := &mockStore{}
	svc := NewProvider("shannon", store, func(c *Provider) { c.temporality = timeStub })
	table := []struct {
		token  string
		claims *AccessClaims
	}{
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJBcHAxIiwiZXhwIjoxNTgzMzY2NzAwLCJpYXQiOjE1ODMzNjY0MDAsInN1YiI6IlRheWxvciJ9.bmmYJDx5GvGq10H0xIMW01aTOM1T7BztTZ_DxRWfHgE",
			&AccessClaims{
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
		var claims = &AccessClaims{}
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
	store := &mockStore{}
	svc := NewProvider("shannon", store, func(c *Provider) { c.temporality = timeStub })
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
