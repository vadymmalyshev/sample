package users

import (
	"context"
	"strconv"

	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/otp/twofactor/sms2fa"
	"github.com/volatiletech/authboss/otp/twofactor/totp2fa"
)

var (
	assertUser   = &User{}
	assertStorer = &UserStorer{}

	_ authboss.User            = assertUser
	_ authboss.AuthableUser    = assertUser
	_ authboss.ConfirmableUser = assertUser
	_ authboss.LockableUser    = assertUser
	_ authboss.RecoverableUser = assertUser
	_ authboss.ArbitraryUser   = assertUser

	_ totp2fa.User = assertUser
	_ sms2fa.User  = assertUser

	_ authboss.CreatingServerStorer   = assertStorer
	_ authboss.ConfirmingServerStorer = assertStorer
	_ authboss.RecoveringServerStorer = assertStorer
)

type UserStorer struct {
	db *gorm.DB
}

func NewUserStorer(db *gorm.DB) *UserStorer {
	return &UserStorer{db}
}

// Load will look up the user based on the passed the PrimaryID
func (store UserStorer) Load(ctx context.Context, key string) (authboss.User, error) {
	var user User

	notFoundByEmail := store.db.First(&user, "email = ?", key).RecordNotFound()

	if notFoundByEmail {
		notFoundByName := store.db.First(&user, "login = ?", key).RecordNotFound()
		if notFoundByName {
			notFoundByToken := store.db.First(&user, "oauth_access_token = ?", key).RecordNotFound()
			if notFoundByToken {
				if _, err := strconv.Atoi(key); err == nil {
					notFoundByID := store.db.First(&user, "id = ?", key).RecordNotFound()
					if notFoundByID {
						return nil, authboss.ErrUserNotFound
					}
				} else {
					return nil, authboss.ErrUserNotFound
				}
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"email": user.Email,
	}).Info("user loaded by email")

	return &user, nil
}

// Save persists the user in the database, this should never
// create a user and instead return ErrUserNotFound if the user
// does not exist.
func (store UserStorer) Save(ctx context.Context, user authboss.User) error {
	u := user.(*User)
	store.db.Save(&u)
	return nil
}

func (store UserStorer) New(ctx context.Context) authboss.User {
	return &User{}
}

func (store UserStorer) Create(ctx context.Context, user authboss.User) error {
	u := user.(*User)
	err := store.db.Create(u).Error

	if err != nil {
		return authboss.ErrUserFound
	}

	logrus.Infof("user created", logrus.Fields{
		"email": u.Email,
	})

	return nil
}

// LoadByConfirmSelector looks a user up by confirmation token
func (store UserStorer) LoadByConfirmSelector(ctx context.Context, selector string) (authboss.ConfirmableUser, error) {
	var user User

	err := store.db.Where(&User{ConfirmSelector: selector}).First(&user).Error
	return &user, err
}

// LoadByRecoverSelector looks a user up by confirmation selector
func (store UserStorer) LoadByRecoverSelector(ctx context.Context, selector string) (authboss.RecoverableUser, error) {
	var user User

	err := store.db.Where(&User{RecoverSelector: selector}).First(&user).Error
	return &user, err
}

// token storage
func (store UserStorer) AddRememberToken(ctx context.Context, pid, token string) error {
	tok := RememberToken{ Pid: pid, Token: token}
	store.db.Save(&tok)

	return nil
}

func (store UserStorer) DelRememberTokens(ctx context.Context, pid string) error {
	store.db.Delete(RememberToken{}, "pid = ?", pid)
	return nil
}

func (store UserStorer) UseRememberToken(ctx context.Context, pid, token string) error {
	store.db.Delete(RememberToken{}, "token = ?", token)
	return nil
}

