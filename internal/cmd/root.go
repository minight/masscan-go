package cmd

import (
	"context"
	"github.com/minight/masscan-go/pkg/log"
	"github.com/minight/masscan-go/pkg/masscan"
)

func Run(loglevel string, logformat string) {
	log, err := log.SetupLogger(loglevel, logformat)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to setup logger")
	}

	if err := masscan.Run(context.TODO(), "en0", log); err != nil {
		log.Fatal().Err(err).Msg("failed to run")
	}
}
