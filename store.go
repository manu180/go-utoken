package token

// Refresh Token - Claims (key-value) store
type Store interface {
	Get(rt string) (*AccessClaims, error)
	Set(rt string, cl *AccessClaims) error
	Del(rt string) (int64, error)
}
