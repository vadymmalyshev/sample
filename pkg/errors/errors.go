package errorss

import "errors"

var (
	ErrUserNotFound     = errors.New("user wasn't found")
	ErrNoChallenge      = errors.New("challenge code was'nt provided")
	ErrHydraAcceptLogin = errors.New("hydra can't accept login")
)
