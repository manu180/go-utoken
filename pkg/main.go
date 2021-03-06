package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/manu180/go-utoken"
	"time"
)

const (
	prefix      string        = "utoken"
	addr        string        = "pearlfish.redistogo.com:10339"
	pwd         string        = "cb6df9f0c09071be97daee420804dba2"
	db          int           = 0
	idleTimeout time.Duration = time.Second * 90
	exp         time.Duration = time.Minute * 1
)

func main() {
	store := token.NewRediStore(prefix, addr, pwd, db, idleTimeout, exp)

	rt := "XXXX53"
	claims := &token.AccessClaims{
		jwt.StandardClaims{
			Audience:  "App1",
			Subject:   "Taylor",
			ExpiresAt: time.Now().Add(time.Minute * 5).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	store.Set(rt, claims)
	store.Get(rt)
}
