package cmd

import (
	"bufio"
	"context"
	"github.com/minight/masscan-go/pkg/convert"
	"github.com/minight/masscan-go/pkg/log"
	"github.com/minight/masscan-go/pkg/masscan"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"inet.af/netaddr"
	"os"
	"sync"
)

const (
	MaxChunkSize = 1000
)

func Run(loglevel string, logformat string, input string, ports []uint) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log, err := log.SetupLogger(loglevel, logformat)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to setup logger")
	}

	in, out, err := masscan.Run(ctx, "en0", log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to run")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := WriteResultsFrom(ctx, log, out); err != nil {
			log.Error().Err(err).Msg("failed to write results")
		}
	}()

	if err := ReadInputTo(ctx, log, input, convert.ConvertSlice[uint, uint16](ports), in); err != nil {
		log.Error().Err(err).Msg("failed to read inputs")
	}

	wg.Wait()
}

func ReadInputTo(ctx context.Context, log zerolog.Logger, input string, ports []uint16, out chan<- masscan.Targets) error {
	log.Trace().Msg("starting input reader")

	defer func() {
		log.Trace().Msg("closing channel")

		close(out)
	}()
	var err error
	if input == "-" {
		f, err := os.Open(input)
		if err != nil {
			return errors.Wrap(err, "failed to open file")
		}
		r := bufio.NewScanner(f)
		err = ReadScannerTo(ctx, log, r, ports, out)
	} else {
		r := bufio.NewScanner(os.Stdin)
		err = ReadScannerTo(ctx, log, r, ports, out)
	}
	if err != nil {
		return errors.Wrap(err, "failed to read scanner to")
	}

	return nil
}

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

func WriteResultsFrom(ctx context.Context, log zerolog.Logger, in <-chan masscan.Res) error {
	log.Trace().Msg("starting results writer")

	for {
		select {
		case <-ctx.Done():
			return nil
		case v, ok := <-in:
			if v.Dst.Nil() && !ok {
				return nil
			}
			log.Info().Str("ip", v.Dst.IP.String()).
				Uint16("port", v.Dst.Port).
				Str("state", "open").Send()
		}
	}

	return nil
}
