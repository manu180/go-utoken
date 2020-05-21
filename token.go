package token

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
)

var (
	errInvalidSigningMethod = errors.New("Invalid signing method.")
)

type Token struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	Claims  Claims `json:"claims"`
}

// Provides abstraction for Token's Claims
type Claims interface {
	Valid() error
}

type AccessClaims struct {
	jwt.StandardClaims
}

type OptAccessClaims func(*AccessClaims)

func NewAccessClaims(opt ...OptAccessClaims) *AccessClaims {
	c := &AccessClaims{}
	for _, v := range opt {
		v(c)
	}
	return c
}

func Aud(aud string) OptAccessClaims {
	return func(c *AccessClaims) {
		c.Audience = aud
	}
}

func Sub(sub string) OptAccessClaims {
	return func(c *AccessClaims) {
		c.Subject = sub
	}
}

func Exp(p *Provider) OptAccessClaims {
	return func(c *AccessClaims) {
		c.ExpiresAt = p.temporality().Add(p.accessExp).UTC().Unix()
	}
}

func Iat(p *Provider) OptAccessClaims {
	return func(c *AccessClaims) {
		c.ExpiresAt = p.temporality().UTC().Unix()
	}
}
