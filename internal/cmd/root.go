package cmd

import (
	"bufio"
	"context"
	"os"
	"sync"

	"github.com/minight/masscan-go/pkg/convert"
	"github.com/minight/masscan-go/pkg/log"
	"github.com/minight/masscan-go/pkg/masscan"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"inet.af/netaddr"
)

const (
	MaxChunkSize = 1024
)

func Run(loglevel string, logformat string, input string, ports []uint, rate int, retries int) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger, err := log.SetupLogger(loglevel, logformat)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to setup logger")
	}

	resultLogger, err := log.ResultWriter(logformat)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to setup resultwriter")
	}

	in, out, err := masscan.Run(ctx, "en0", logger, rate, retries)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to run")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := WriteResultsFrom(ctx, logger, resultLogger, out); err != nil {
			logger.Error().Err(err).Msg("failed to write results")
		}
	}()

	if err := ReadInputTo(ctx, logger, input, convert.ConvertSlice[uint, uint16](ports), in); err != nil {
		logger.Error().Err(err).Msg("failed to read inputs")
	}

	wg.Wait()
}

// ReadInputTo will open the input as a file and begin buffered writing of the contents to the channel
// This will assume each line is one ip address. This does not support hostnames
func ReadInputTo(ctx context.Context, log zerolog.Logger, input string, ports []uint16, out chan<- masscan.Targets) error {
	log.Trace().Msg("starting input reader")

	defer func() {
		log.Trace().Msg("closing channel")

		close(out)
	}()
	var err error

	// pick the input stream being either stdin or the file
	f := os.Stdin
	if input != "-" {
		log.Info().Str("filename", input).Msg("reading from file")
		f, err = os.Open(input)
		if err != nil {
			return errors.Wrap(err, "failed to open file")
		}
	} else {
		log.Info().Msg("reading from stdin")
	}

	err = ReadScannerTo(ctx, log, bufio.NewScanner(f), ports, out)
	if err != nil {
		return errors.Wrap(err, "failed to read scanner to")
	}

	return nil
}

// PrepareDst will convert the in slice and ports into the appropriate format for masscan
func PrepareDst(log zerolog.Logger, in []string, ports []uint16) (ret masscan.Targets) {
	ret.Ports = ports
	for _, v := range in {
		ip, err := netaddr.ParseIP(v)
		if err != nil {
			log.Error().Err(err).Msg("failed to parse ip address")
			continue
		}

		ret.IPs = append(ret.IPs, ip)
	}
	return ret
}

// ReadScannerTo will perform a chunked read of the scanner and publish it to masscan
// we chunk the results to optimize for huge files and give us more manageable chunks
func ReadScannerTo(ctx context.Context, log zerolog.Logger, r *bufio.Scanner, ports []uint16, out chan<- masscan.Targets) error {
	lines := make([]string, 0)
	for r.Scan() {
		line := r.Text()
		lines = append(lines, line)
		if len(lines) > MaxChunkSize {
			select {
			case <-ctx.Done():
				return nil
			case out <- PrepareDst(log, lines, ports):
				log.Trace().Msg("scheduling")
			}
			lines = lines[:0]
		}
	}

	if len(lines) > 0 {
		select {
		case <-ctx.Done():
			return nil
		case out <- PrepareDst(log, lines, ports):
			log.Trace().Msg("scheduling")
		}
	}

	return nil
}

// WriteResultsFrom will write the results from the channel to the resultLogger
// This only contains basic information like the ip, port and state and timestamp of the event when logged
func WriteResultsFrom(ctx context.Context, log zerolog.Logger, resultLogger zerolog.Logger, in <-chan masscan.Res) error {
	log.Trace().Msg("starting results writer")

	for {
		select {
		case <-ctx.Done():
			return nil
		case v, ok := <-in:
			if v.Dst.Nil() && !ok {
				return nil
			}
			resultLogger.Log().Str("ip", v.Dst.IP.String()).
				Uint16("port", v.Dst.Port).
				Str("state", v.State.String()).Send()
		}
	}

	return nil
}
