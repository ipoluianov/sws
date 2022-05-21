package main

import (
	"github.com/gazercloud/sws/app"
	"github.com/gazercloud/sws/application"
	"github.com/gazercloud/sws/logger"
)

func main() {
	application.Name = "sws"
	application.ServiceName = "sws"
	application.ServiceDisplayName = "sws"
	application.ServiceDescription = "sws"
	application.ServiceRunFunc = app.RunAsService
	application.ServiceStopFunc = app.StopService

	logger.Init(logger.CurrentExePath() + "/logs")

	if !application.TryService() {
		app.RunDesktop()
	}
}
