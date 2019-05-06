package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"git.tor.ph/hiveon/idp/internal/hydra"
	"git.tor.ph/hiveon/idp/models/users"
	"github.com/go-chi/chi"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/authboss"
	"golang.org/x/oauth2"
	"gopkg.in/resty.v1"
)

func (a Auth) challengeCode(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("login_challenge")
	if len(challenge) == 0 { // obtain login challenge
		oauthClient := initOauthClient(a.conf.Hydra)

		state, err := stateTokenGenerator()
		if err != nil {
			logrus.Error("login token failed generation")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			logrus.Debugf("server err, can't generate auth token")
			return
		}

		c := http.Cookie{
			Name:     cookieLoginState,
			Value:    state,
			Path:     "/",
			HttpOnly: true,
		}

		http.SetCookie(w, &c)
		redirectUrl := oauthClient.AuthCodeURL(state)

		a.render.JSON(w, 200, map[string]string{"redirectURL": redirectUrl})
		return
	}

	challengeResp, err := hydra.CheckChallengeCode(challenge, a.conf.Hydra)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		logrus.Debugf("wrong login challenge")
		return
	}
	challengeCode := challengeResp.Challenge
	authboss.PutSession(w, "Challenge", challengeCode)

	a.render.JSON(w, 200, map[string]string{"challenge": challengeCode})
	return
}

func (a Auth) callbackToken(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	fmt.Println("Code: ", code)

	oauthClient := initOauthClient(a.conf.Hydra)

	stateToken, err := r.Cookie(cookieLoginState)
	if err != nil {
		logrus.Infoln("state token absent")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		logrus.Debugf("Can't obtain authorization token\n")
		return
	}

	if stateToken.Value != state {
		logrus.Infof("invalid oauth state, cookie: '%s', URL: '%s'\n", stateToken.Value, state)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		logrus.Debugf("Can't obtain authorization token\n")
		return
	}

	token, err := oauthClient.Exchange(oauth2.NoContext, code)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		logrus.Debugf("Can't obtain authorization token")
		return
	}

	var introToken swagger.OAuth2TokenIntrospection
	introspectUrl := a.conf.Hydra.Introspect

	res, err := resty.R().SetFormData(map[string]string{"token": token.AccessToken}).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Accept", "application/json").Post(introspectUrl)

	err = json.Unmarshal(res.Body(), &introToken)
	user, err := a.authBoss.Storage.Server.Load(context.TODO(), introToken.Sub)

	if user != nil && err == nil {
		user1 := user.(*users.User)
		user1.PutOAuth2AccessToken(token.AccessToken)
		user1.PutOAuth2RefreshToken(token.RefreshToken)
		user1.PutOAuth2Expiry(token.Expiry)

		a.authBoss.Config.Storage.Server.Save(r.Context(), user1)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusNoContent)
		return
	}

	SetAccessTokenCookie(w, token.AccessToken)
}

func (a Auth) acceptConsent(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("consent_challenge")

	if len(challenge) == 0 {
		ro := authboss.RedirectOptions{
			Code:         http.StatusTemporaryRedirect,
			RedirectPath: "/",
			Failure:      "You have no consent challenge",
		}
		a.authBoss.Core.Redirector.Redirect(w, r, ro)
		return
	}

	url, err := hydra.AcceptConsentChallengeCode(challenge, a.conf.Hydra)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		logrus.Debugf("consent challenge code isn't right")
		return
	}

	logrus.Debugf("Consent code accepted")

	var oauth2ConsentCSRF *http.Cookie
	oauth2AuthCSRF, _ := r.Cookie(cookieAuthenticationCSRFName)

	k := r.Cookies()
	for i, v := range k {
		if v.Name == cookieConsentCSRFName {
			oauth2ConsentCSRF = k[i]
		}
	}

	res, err := resty.
		SetCookie(oauth2ConsentCSRF).
		SetCookie(oauth2AuthCSRF).
		R().
		SetHeader("Accept", "application/json").
		Get(url)

	if err != nil {
		a.render.JSON(w, 422, &ResponseError{
			Status:  "error",
			Success: false,
			Error:   "no consent csrf token has been provided",
		})
	}

	accessToken := res.RawResponse.Header.Get("Set-Cookie")
	splitToken := strings.Split(accessToken, " ")
	if len(splitToken) < 2 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		logrus.Error("Can't obtain access token!")
		return
	}

	w.Header().Set("access_token", splitToken[1])
}

func (a Auth) handleLogin(challenge string, w http.ResponseWriter, r *http.Request) (bool, error) {
	if challenge == "" {
		a.render.JSON(w, 422, &ResponseError{
			Status:  "error",
			Success: false,
			Error:   "no challenge code has been provided",
		})

		return true, nil
	}

	user, err := a.authBoss.LoadCurrentUser(&r)
	if user != nil && err == nil {
		user := user.(*users.User)

		resp, errConfirm := hydra.ConfirmLogin(user.ID, false, challenge, a.conf.Hydra)
		if errConfirm != nil || resp.RedirectTo == "" {
			logrus.Debugf("probably challenge has been expired")
			a.render.JSON(w, 422, &ResponseError{
				Status:  "error",
				Success: false,
				Error:   "challenge code has been expired",
			})
			return true, nil
		}

		oauth2AuthCSRF, oauth2Err := r.Cookie(cookieAuthenticationCSRFName)
		loginStateToken, loginStateErr := r.Cookie(cookieLoginState)

		cookieArray := []*http.Cookie{}
		resty.DefaultClient.Cookies = cookieArray

		if oauth2Err != nil || loginStateErr != nil {
			if oauth2Err != nil {
				logrus.Infof("%s token absent! login rejected\n", cookieAuthenticationCSRFName)
			}
			if loginStateErr != nil {
				logrus.Infof("%s token absent! login rejected\n", cookieLoginState)
			}
			a.render.JSON(w, 422, &ResponseError{
				Status:  "error",
				Success: false,
				Error:   "auth token absent",
			})
			return true, nil
		}

		res, err := resty.
			SetCookie(oauth2AuthCSRF).
			SetCookie(loginStateToken).
			R().
			SetHeader("Accept", "application/json").
			Get(resp.RedirectTo)

		if err != nil {
			a.render.JSON(w, 422, &ResponseError{
				Status:  "error",
				Success: false,
				Error:   "no csrf token has been provided",
			})
			return true, nil
		}

		accessToken := res.RawResponse.Header.Get("access_token")
		if accessToken == "" {
			a.render.JSON(w, 422, &ResponseError{
				Status:  "error",
				Success: false,
				Error:   "No access token has been obtained",
			})
			return true, nil
		}

		SetAccessTokenCookie(w, accessToken)

		a.render.JSON(w, 200, map[string]string{
			"access_token": accessToken,
			"token_type":   "bearer",
		})
	}
	return true, nil
}

func (a Auth) getUserByEmail(w http.ResponseWriter, r *http.Request) {
	user, err := a.getAuthbossUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNoContent)
		return
	}

	a.render.JSON(w, 200, user)
}

func (a Auth) loginChallenge(w http.ResponseWriter, r *http.Request) {
	oauthClient := initOauthClient(a.conf.Hydra)
	redirectURL := oauthClient.AuthCodeURL("state123")

	a.render.JSON(w, 200, map[string]string{"redirectURL": redirectURL})
}

func (a Auth) refreshTokenByEmail(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	user, err := a.authBoss.Config.Storage.Server.Load(r.Context(), email)
	if err != nil {
		a.render.JSON(w, 500, map[string]string{"error": "user not found"})
		return
	}

	a.RefreshToken(w, r, user)
}

func (a Auth) getUserInfo(w http.ResponseWriter, r *http.Request) {
	user, err := a.authBoss.LoadCurrentUser(&r)
	if err != nil {
		a.render.JSON(w, 401, err.Error())
		return
	}
	a.RefreshToken(w, r, user)
}
