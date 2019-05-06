package models

import (
	"git.tor.ph/hiveon/idp/models/users"

	"github.com/jinzhu/gorm"
)

func Migrate(db *gorm.DB) {
	db.AutoMigrate(&users.User{})
	db.AutoMigrate(&users.RememberToken{})
}
