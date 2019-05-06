package auth

import (
	"context"

	"git.tor.ph/hiveon/idp/config"
	"gopkg.in/gomail.v2"

	log "github.com/sirupsen/logrus"
	"github.com/volatiletech/authboss"
)

type authMailer struct {
	config config.MailConfig
	dialer *gomail.Dialer
}

func NewMailer() *authMailer {
	config, _ := config.GetMailConfig()

	dialer := gomail.NewDialer(config.SMTP, config.Port, config.User, config.Password)

	return &authMailer{config, dialer}
}

func (m *authMailer) Send(c context.Context, email authboss.Email) error {
	message := gomail.NewMessage()
	message.SetHeader("From", m.config.From)
	message.SetHeader("To", email.To...)
	message.SetHeader("Cc", email.Cc...)
	message.SetHeader("Subject", email.Subject)

	if len(email.HTMLBody) == 0 {
		message.SetBody("text/plain", email.TextBody)
	} else {
		message.SetBody("text/html", email.HTMLBody)
	}

	if err := m.dialer.DialAndSend(message); err != nil {
		log.Error(err)

		return err
	}

	log.Info("Message sent: ", message)
	return nil
}
