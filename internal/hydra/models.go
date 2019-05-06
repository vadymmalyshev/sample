package hydra

type LoginRequest struct {
	// Remember, if set to true, tells ORY Hydra to remember this user by telling the user agent (browser) to store
	// a cookie with authentication data. If the same user performs another OAuth 2.0 Authorization Request, he/she
	// will not be asked to log in again.
	Remember bool `json:"remember"`

	// RememberFor sets how long the authentication should be remembered for in seconds. If set to `0`, the
	// authorization will be remembered indefinitely.
	RememberFor int `json:"remember_for"`

	// ACR sets the Authentication AuthorizationContext Class Reference value for this authentication session. You can use it
	// to express that, for example, a user authenticated using two factor authentication.
	ACR string `json:"acr"`

	// Subject is the user ID of the end-user that authenticated.
	Subject string `json:"subject"`
}

type LoginResponse struct {
	RedirectTo string `json:"redirect_to"`
}
