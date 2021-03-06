package log

import (
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"os"
	"testing"
)

var (
	ErrInvalidFormat = errors.New("unexpected log format. opts: pretty,json,text")
)

func TestLogger(t *testing.T, level zerolog.Level) zerolog.Logger {
	log := zerolog.New(os.Stderr)
	log = log.Level(level)
	log = log.With().Timestamp().Logger()
	return log
}

func SetupLogger(level string, format string) (zerolog.Logger, error) {
	log := zerolog.New(os.Stderr)
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		return log, err
	}
	log = log.Level(lvl)

	log = log.With().Timestamp().Logger()

	switch format {
	case "pretty":
		log = log.Output(zerolog.ConsoleWriter{
			Out: os.Stderr,
		})
	case "json":
	case "text":
		log = log.Output(zerolog.ConsoleWriter{
			Out:     os.Stderr,
			NoColor: true,
		})
	default:
		return log, ErrInvalidFormat
	}

	return log, nil
}
