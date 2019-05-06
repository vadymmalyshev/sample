package users

import "github.com/jinzhu/gorm"

type RememberToken struct {
	gorm.Model
	Pid   string `gorm:"not null"`
	Token string `gorm:"not null"`
}

func (RememberToken) TableName() string {
	return "ab_remember_tokens"
}

// Put pid into element
func (t *RememberToken) PutPid(pid string) { t.Pid = pid }

// Put token into element
func (t *RememberToken) PutToken(token string) { t.Token = token }

// Get pid from element
func (t *RememberToken) GetPid() string { return t.Pid}

// Get token from element
func (t *RememberToken) GetToken() string { return t.Token }