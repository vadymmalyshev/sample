package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"git.tor.ph/hiveon/idp/config"
	"git.tor.ph/hiveon/idp/models/users"
	//"github.com/gorilla/csrf"
	"io/ioutil"
	"net/http"

	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/volatiletech/authboss"
	"golang.org/x/oauth2"
	"gopkg.in/resty.v1"
)

func (a Auth) handleUserSession(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		user, err := a.getUserFromHydraSession(w, r)
		if err != nil || user == nil {
			authboss.DelAllSession(w, a.authBoss.Config.Storage.SessionStateWhitelistKeys)
			authboss.DelKnownSession(w)
			authboss.DelKnownCookie(w)

			logrus.Error(err.Error())
		} else {
			r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyPID, user.(*users.User).Email))
		}
		handler.ServeHTTP(w, r)
	})
}

func (a Auth) dataInjector(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := a.layoutData(w, &r, "")
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, data))
		handler.ServeHTTP(w, r)
	})
}

// layoutData is passing pointers to pointers be able to edit the current pointer
// to the request. This is still safe as it still creates a new request and doesn't
// modify the old one, it just modifies what we're pointing to in our methods so
// we're able to skip returning an *http.Request everywhere
func (a Auth) layoutData(w http.ResponseWriter, r **http.Request, redirect string) authboss.HTMLData {
	currentUserName := ""
	userInter, err := a.authBoss.LoadCurrentUser(r)
	if userInter != nil && err == nil {
		currentUserName = userInter.(*users.User).Login
	}

	return authboss.HTMLData{
		"loggedin":          userInter != nil,
		"current_user_name": currentUserName,
		//"csrf_token":        nosurf.Token(*r),
		"flash_success": authboss.FlashSuccess(w, *r),
		"flash_error":   authboss.FlashError(w, *r),
		"redirectURL":   redirect,
	}
}

/*func debugMw(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("\n%s %s %s\n", r.Method, r.URL.Path, r.Proto)

		session, err := sessionStore.Get(r, IDPSessionName)
		if err == nil {
			fmt.Print("Session: ")
			first := true
			for k, v := range session.Values {
				if first {
					first = false
				} else {
					fmt.Print(", ")
				}
				fmt.Printf("%s = %v", k, v)
			}
			fmt.Println()
		}
		// fmt.Println("Database:")
		// for _, u := range database.Users {
		// 	fmt.Printf("! %#v\n", u)
		// }
		if val := r.Context().Value(authboss.CTXKeyData); val != nil {
			fmt.Printf("CTX Data: %s", spew.Sdump(val))
		}
		if val := r.Context().Value(authboss.CTXKeyValues); val != nil {
			fmt.Printf("CTX Values: %s", spew.Sdump(val))
		}

		handler.ServeHTTP(w, r)
	})
}*/

func initOauthClient(hydraConf config.HydraConfig) *oauth2.Config {
	client := GetClient(hydraConf)
	oauthConfig := &oauth2.Config{
		ClientID:     hydraConf.ClientID,
		ClientSecret: hydraConf.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  hydraConf.API + "/oauth2/auth",
			TokenURL: hydraConf.API + "/oauth2/token",
		},
		RedirectURL: client.RedirectUris[0],
		Scopes:      getScopes(),
	}

	return oauthConfig
}

func GetClient(hydraConf config.HydraConfig) swagger.OAuth2Client {

	clientUrl := hydraConf.Admin + "/clients/" + hydraConf.ClientID
	res, err := resty.R().Get(clientUrl)
	if err != nil {
		log.Info(err)
	}
	var client swagger.OAuth2Client
	json.Unmarshal(res.Body(), &client)
	return client

}

func getScopes() []string {
	return []string{"openid", "offline"}
}

func getChallengeFromURL(r *http.Request, w http.ResponseWriter) (string, string) {
	bodyBytes, _ := ioutil.ReadAll(r.Body)
	b := bodyBytes
	fromURLString := ""
	chalengeString := ""

	var t map[string]string
	json.Unmarshal(b, &t)

	if t["fromURL"] != "" {
		fromURLString = t["fromURL"]

	}
	if t["login_challenge"] != "" {
		chalengeString = t["login_challenge"]

	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	return fromURLString, chalengeString
}

func setRedirectURL(redirectURL string, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"redirectURL": %q}`, redirectURL)
	w.WriteHeader(http.StatusOK)
}

func (a Auth) checkRegistrationCredentials(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if  r.URL.Path == "/api/recover/end" && r.Method == "POST" {
			//abUser, _ := a.authBoss.LoadCurrentUser(&r)
			a.handleLogin("", w, r) // test
		}
		if r.URL.Path == "/api/register" && r.Method == "POST" {
			var values map[string]string

			b, err := ioutil.ReadAll(r.Body)
			bodyBytes :=b

			if err != nil {
				fmt.Println(err, "failed to read http body")
			}

			if err = json.Unmarshal(b, &values); err != nil {
				fmt.Println(err, "failed to parse json http body")
			}
			r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

			login := values["login"]
			pidUser, err := a.authBoss.Storage.Server.Load(r.Context(), login)
			if pidUser != nil {
				a.render.JSON(w, http.StatusUnprocessableEntity, &ResponseError{
					Status:  "error",
					Success: false,
					Error:   fmt.Sprintf("Username %s has already taken", login),
				})
				return
			}

			email := values["email"]
			pidUser, err = a.authBoss.Storage.Server.Load(r.Context(), email)
			if pidUser != nil {
				a.render.JSON(w, http.StatusUnprocessableEntity, &ResponseError{
					Status:  "error",
					Success: false,
					Error:   fmt.Sprintf("Email %s has already taken", email),
				})
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}
