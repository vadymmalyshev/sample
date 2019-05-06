package auth

import (
	clientState "github.com/volatiletech/authboss-clientstate"
	"github.com/volatiletech/authboss/remember"

	"encoding/base64"
	"net/http"
	"regexp"

	"git.tor.ph/hiveon/idp/models/users"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss-renderer"
	"github.com/volatiletech/authboss/auth"
	"github.com/volatiletech/authboss/defaults"
	"github.com/volatiletech/authboss/otp/twofactor/totp2fa"
	"github.com/volatiletech/authboss/recover"
	"github.com/volatiletech/authboss/register"
)

func initSessionStorer() clientState.SessionStorer {
	//TODO move to config
	sessionStoreKey, _ := base64.StdEncoding.DecodeString(`AbfYwmmt8UCwUuhd9qvfNA9UCuN1cVcKJN1ofbiky6xCyyBj20whe40rJa3Su0WOWLWcPpO1taqJdsEI/65+JA==`)

	sessionStore := clientState.NewSessionStorer(IDPSessionName, sessionStoreKey, nil)

	cstore := sessionStore.Store.(*sessions.CookieStore)

	cstore.Options.HttpOnly = false
	cstore.Options.Secure = false

	return sessionStore
}

func initCookieStorer() clientState.CookieStorer {
	cookieStoreKey, _ := base64.StdEncoding.DecodeString(`NpEPi8pEjKVjLGJ6kYCS+VTCzi6BUuDzU0wrwXyf5uDPArtlofn2AG6aTMiPmN3C909rsEWMNqJqhIVPGP3Exg==`)
	cookieStore := clientState.NewCookieStorer(cookieStoreKey, nil)
	cookieStore.Domain = "localhost"
	cookieStore.HTTPOnly = false
	cookieStore.Secure = false

	return cookieStore
}

func initAuthBoss(serviceAddr string, db *gorm.DB, sessionStorer clientState.SessionStorer, cookieStorer clientState.CookieStorer) *authboss.Authboss {
	ab := authboss.New()

	ab.Config.Paths.RootURL = serviceAddr
	ab.Config.Storage.Server = users.NewUserStorer(db)
	ab.Config.Storage.SessionState = sessionStorer
	ab.Config.Storage.CookieState = cookieStorer
	ab.Config.Storage.SessionStateWhitelistKeys = []string{"Authorization", "oauth2_authentication_csrf", "access_token"}

	ab.Config.Core.ViewRenderer = defaults.JSONRenderer{}

	ab.Config.Modules.RegisterPreserveFields = []string{"email", "login", "name"}

	ab.Config.Modules.TOTP2FAIssuer = "HiveonID"
	ab.Config.Modules.TwoFactorEmailAuthRequired = false
	ab.Config.Modules.RecoverLoginAfterRecovery = true

	defaults.SetCore(&ab.Config, *flagAPI, false)

	ab.Config.Core.Mailer = NewMailer()
	ab.Config.Core.MailRenderer = abrenderer.NewEmail("/", tplPath)

	emailRule := defaults.Rules{
		FieldName: "email", Required: true,
		MatchError: "Must be a valid e-mail address",
		MustMatch:  regexp.MustCompile(`.*@.*\.[a-z]+`),
	}
	passwordRule := defaults.Rules{
		FieldName: "password", Required: true,
		MinLength: 4,
	}
	nameRule := defaults.Rules{
		FieldName: "name", Required: false,
		AllowWhitespace: true,
	}
	loginRule := defaults.Rules{
		FieldName: "login", Required: true,
		MinLength: 2,
	}

	ab.Config.Core.BodyReader = defaults.HTTPBodyReader{
		ReadJSON: *flagAPI,
		Rulesets: map[string][]defaults.Rules{
			"register":      {emailRule, passwordRule, nameRule, loginRule},
			"recover_start": {emailRule},
			"recover_end":   {passwordRule},
		},
		Confirms: map[string][]string{
			// 	"register":    {"password", authboss.ConfirmPrefix + "password"},
			"recover_end": {"password", authboss.ConfirmPrefix + "password"},
		},
		Whitelist: map[string][]string{
			"register": []string{"email", "name", "login", "password"},
		},
	}

	ab.Config.Paths.RecoverOK = recoverSentURL
	// Load our template of recover sent message to AB renderer
	ab.Config.Core.ViewRenderer.Load(recoverSentTPL)
	// Handle recover sent
	ab.Config.Core.Router.Get(recoverSentURL, ab.Core.ErrorHandler.Wrap(func(w http.ResponseWriter, req *http.Request) error {
		return ab.Config.Core.Responder.Respond(w, req, http.StatusOK, recoverSentTPL, nil)
	}))

	modAuth := auth.Auth{}
	if err := modAuth.Init(ab); err != nil {
		logrus.Panicf("can't initialize authboss's auth mod", err)
	}

	modRegister := register.Register{}
	if err := modRegister.Init(ab); err != nil {
		logrus.Panicf("can't initialize authboss's register mod", err)
	}

	modRecover := recover.Recover{}
	if err := modRecover.Init(ab); err != nil {
		logrus.Panicf("can't initialize authboss's recover mod", err)
	}

	modTotp := &totp2fa.TOTP{Authboss: ab}
	if err := modTotp.Setup(); err != nil {
		logrus.Panicf("can't initialize authboss's totp2fa mod", err)
	}

	modRemember := remember.Remember{}
	if err := modRemember.Init(ab); err != nil {
		logrus.Panicf("can't initialize authboss's remember mod", err)
	}

	return ab
}
