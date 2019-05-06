package auth

const (
	cookieAuthenticationCSRFName = "oauth2_authentication_csrf"
	cookieConsentCSRFName        = "oauth2_consent_csrf"
	cookieLoginState             = "login_csrftoken"

	IDPSessionName = "idp_session"

	recoverSentURL = "/recover/sent"
	recoverSentTPL = "recover_sent"

	tplPath = "views/"

	SessionCookieSecure = false
	// SessionCookieHTTPOnly describes if the cookies should be accessible from HTTP requests only (no JS)
	SessionCookieHTTPOnly = false
	// SessionCookieMaxAge holds long an authenticated session should be valid in seconds
	SessionCookieMaxAge = 30 * 24 * 60 * 60
)
