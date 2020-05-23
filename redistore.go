package token

import (
	"errors"
	"fmt"
	"github.com/gomodule/redigo/redis"
	"time"
)

var (
	errKeyNotFound = errors.New("Key does not exist.")
)

// Refresh token that satisfies the Store interface
type rediStore struct {
	prefix string
	exp    time.Duration
	pool   *redis.Pool
}

func NewRediStore(prefix string, addr string, pwd string, db int, exp time.Duration) *rediStore {
	s := rediStore{
		prefix: prefix + ":",
		exp:    exp,
		pool:   newPool(addr, pwd, db),
	}
	if err := s.ping(); err != nil {
		panic("Unable to connect to redis " + err.Error())
	}
	fmt.Printf("Connection to Redis '%v' successfully established!\n\n", addr)
	return &s
}

func newPool(addr string, pwd string, db int) *redis.Pool {
	return &redis.Pool{
		// Maximum number of idle connections in the pool.
		MaxIdle: 80,
		// max number of connections
		MaxActive: 12000,
		// Dial is an application supplied function for creating and configuring a connection.
		// on heroku it looks like that : redis://username:password@host:port
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", addr)
			if err != nil {
				panic(err.Error())
			}
			// authenticate with password
			if _, err := c.Do("AUTH", pwd); err != nil {
				c.Close()
				return nil, err
			}
			// select the database
			if _, err := c.Do("SELECT", db); err != nil {
				c.Close()
				return nil, err
			}
			return c, err
		},
	}
}

// ping tests connectivity for redis (PONG should be returned)
func (s *rediStore) ping() error {
	c := s.getConn()
	// Close method must be called when the application is done with the connection
	defer c.Close()
	// Send PING command to Redis
	_, err := c.Do("PING")
	if err != nil {
		return err
	}
	// PING command returns a Redis "Simple String"
	// Use redis.String to convert the interface type to string
	// s, err := redis.String(pong, err)
	return nil
}

func (s *rediStore) getConn() redis.Conn {
	return s.pool.Get()
}

func (s *rediStore) Get(rt string) (*AccessClaims, error) {
	c := s.getConn()
	defer c.Close()
	v, err := redis.Values(c.Do("HGETALL", s.prefix+rt))
	if err != nil {
		return nil, err
	}
	if len(v) < 1 {
		return nil, errKeyNotFound
	}
	var claims = AccessClaims{}
	err = redis.ScanStruct(v, &claims)
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

func (s *rediStore) Set(rt string, cl *AccessClaims) error {
	c := s.getConn()
	defer c.Close()
	// !!! as of Redis 4.0 HMSET (-> HSET) is considered as deprecated !!!
	// Heroku RedisToGo still runs with 3.2.12 as default
	_, err := c.Do("HMSET", redis.Args{s.prefix + rt}.AddFlat(cl)...)
	if err != nil {
		return err
	}
	return nil
}

func (s *rediStore) Del(rt string) (int64, error) {
	c := s.getConn()
	defer c.Close()
	v, err := c.Do("DEL", s.prefix+rt)
	if err != nil {
		return 0, err
	}
	i := v.(int64)
	return i, err
}
