package main

import (
	ginutils "git.tor.ph/hiveon/idp/pkg/gin"

	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"git.tor.ph/hiveon/idp/auth"
	"git.tor.ph/hiveon/idp/config"
	"git.tor.ph/hiveon/idp/models"
	"git.tor.ph/hiveon/idp/pkg/log"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/gogap/logrus_mate"
	"github.com/sirupsen/logrus"
)

func init() {
	logrus_mate.Hijack(
		logrus.StandardLogger(),
		logrus_mate.ConfigString(
			`{formatter.name = "text"}`,
		),
	)
}

func main() {
	flag.Parse()
	conf := config.InitViperConfig()

	r := gin.New()

	db := config.DB(conf.IDP.DB)
	defer db.Close()

	models.Migrate(db)

	logger := log.NewLogger(log.Config{
		Level:  "debug",
		Format: "text",
	})

	r.Use(ginutils.Middleware(logger))

	r.Use(static.Serve("/assets", static.LocalFile("./views/assets", true)))

	authObj := auth.NewAuth(r, db, conf)
	authObj.Init()

	errs := make(chan error, 2)

	go func() {
		logrus.Infof("api-mode. IDP has started on http://%s", conf.ServerConfig.Addr)
		//errs <- r.RunTLS(serverConfig.Addr, "./config/certs/hiveon.local.crt", "./config/certs/hiveon.local.key")
		errs <- r.Run(conf.ServerConfig.Addr)
	}()

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	logrus.Info("terminated", <-errs)

}
