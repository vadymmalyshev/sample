package auth

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"git.tor.ph/hiveon/idp/models/users"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"golang.org/x/oauth2"
	"gopkg.in/resty.v1"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/volatiletech/authboss"
)

var (
	flagAPI = flag.Bool("api", true, "configure the app to be an api instead of an html app")
)

type ResponseError struct {
	Status  string `json:"status"`
	Success bool   `json:"success"`
	Error   string `json:"errorMsg"`
}

func (a Auth) getAuthbossUser(r *http.Request) (authboss.User, error) {
	email := chi.URLParam(r, "email")
	user, err := a.authBoss.Config.Storage.Server.Load(r.Context(), email)
	return user, err
}

func (a Auth) getAuthbossUserByEmail(r *http.Request, email string) (authboss.User, error) {
	user, err := a.authBoss.Config.Storage.Server.Load(r.Context(), email)
	return user, err
}

func formatToken(token string) string {
	token = strings.Replace(token, "Authorization=", "", 1)
	token = strings.Replace(token, "; Path=/", "", 1)
	return fmt.Sprintf("Bearer %s", token)
}

func (a Auth) getUserFromHydraSession(w http.ResponseWriter, r *http.Request) (authboss.User, error) {
	reqTokenCookie, err := r.Cookie("Authorization")
	if err != nil {
		return nil, errors.New("authorization token missed")
	}

	reqToken := reqTokenCookie.Value

	if len(reqToken) == 0 {
		return nil, errors.New("authorization token missed")
	}

	splitToken := strings.Split(reqToken, " ")
	if len(splitToken) < 1 {
		return nil, errors.New("token is wrong")
	}

	token := strings.TrimSpace(splitToken[1])
	introspectURL := fmt.Sprintf("%s/oauth2/introspect", a.conf.Hydra.Admin)

	res, err := resty.R().SetFormData(map[string]string{"token": token}).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Accept", "application/json").Post(introspectURL)

	if err != nil {
		return nil, errors.New("can't check token")
	}
	var introToken swagger.OAuth2TokenIntrospection

	if err := json.Unmarshal(res.Body(), &introToken); err != nil {
		return nil, errors.New("can't unmarshall token")
	}

	if introToken.Active == false { //refresh
		rememberCookie, _ := authboss.GetCookie(r, authboss.CookieRemember)
		if rememberCookie == "" {
			return nil, errors.New("Authorization token is not active")
		}

		user, err := a.authBoss.LoadCurrentUser(&r)
		if err != nil {
			return nil, errors.New("can't find user")
		}

		a.RefreshToken(w, r, user)
		return user, nil
	}

	user, err := a.getAuthbossUserByEmail(r, introToken.Sub)
	if err != nil {
		return nil, errors.New("can't find user")
	}

	return user, nil
}

// RefreshToken refreshing token via hydra for specified user
func (a Auth) RefreshToken(w http.ResponseWriter, r *http.Request, abUser authboss.User) {
	user := abUser.(*users.User)
	refreshToken := user.GetOAuth2RefreshToken()
	accessToken := user.GetOAuth2AccessToken()
	expiry := user.GetOAuth2Expiry()
	oauthClient := initOauthClient(a.conf.Hydra)

	if refreshToken == "" {
		http.Error(w, "No refresh token", http.StatusForbidden)
		return
	}

	token := oauth2.Token{RefreshToken: refreshToken, AccessToken: accessToken, Expiry: expiry}
	updatedToken, _ := oauthClient.TokenSource(context.TODO(), &token).Token()

	if updatedToken == nil {
		return
	}

	if accessToken != updatedToken.AccessToken {
		user.PutOAuth2AccessToken(updatedToken.AccessToken)
		user.PutOAuth2RefreshToken(updatedToken.RefreshToken)
		user.PutOAuth2Expiry(updatedToken.Expiry)

		a.authBoss.Config.Storage.Server.Save(r.Context(), user)
	}

	SetAccessTokenCookie(w, updatedToken.AccessToken)

	a.render.JSON(w, 200, map[string]string{
		"access_token": updatedToken.AccessToken,
	})
}
