package cmd

import (
	"bufio"
	"context"
	"os"
	"runtime/pprof"
	"sync"

	"github.com/minight/masscan-go/pkg/convert"
	"github.com/minight/masscan-go/pkg/log"
	"github.com/minight/masscan-go/pkg/masscan"
	"github.com/minight/netaddr"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

const (
	MaxChunkSize = 1024 * 32
)

func Run(loglevel string, logformat string, iface string, input string, ports []uint, rate int, retries int) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger, err := log.SetupLogger(loglevel, logformat)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to setup logger")
	}

	if true {
		f, err := os.Create("/tmp/cpu.profiler2")
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to create profiler")
		}
		logger.Info().Msg("starting cpu profiling")
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	resultLogger, err := log.ResultWriter(logformat)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to setup resultwriter")
	}

	in, out, err := masscan.Run(ctx, iface, logger, rate, retries)
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
// this will chunk the targets into reasonable sizes where they give us a huge fuckoff cidr
func PrepareDst(log zerolog.Logger, in []string, ports []uint16, chunkSize int) (ret []masscan.Targets) {
	t := masscan.Targets{
		Ports: ports,
	}
	for _, v := range in {
		var iprange netaddr.IPRange
		ipprefix, err := netaddr.ParseIPPrefix(v)
		if err != nil {
			// its not an iprange, consider it a normal ip addres
			ipaddr, err2 := netaddr.ParseIP(v)
			if err2 != nil {
				// we failed both so skip
				log.Error().Errs("errors", []error{err, err2}).Msg("failed to parse ip address")
				continue
			}
			// we will construct an ip range of 1 ip
			iprange = netaddr.IPRangeFrom(ipaddr, ipaddr)
		} else {
			iprange = ipprefix.Range()
		}

		// iterate through the ip ranges. Break on the inclusive range, since a /32 is inclusive of 1
		for i := iprange.From(); i.Compare(iprange.To()) <= 0; i = i.Next() {
			t.IPs = append(t.IPs, i)
			if len(t.IPs) >= chunkSize {
				ret = append(ret, t)
				t = masscan.Targets{
					Ports: ports,
				}
			}
		}
	}

	if len(t.IPs) > 0 {
		ret = append(ret, t)
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
			for _, dst := range PrepareDst(log, lines, ports, MaxChunkSize) {
				select {
				case <-ctx.Done():
					return nil
				case out <- dst:
					log.Trace().Msg("scheduling")
				}
			}
			lines = lines[:0]
		}
	}

	if len(lines) > 0 {
		for _, dst := range PrepareDst(log, lines, ports, MaxChunkSize) {
			select {
			case <-ctx.Done():
				return nil
			case out <- dst:
				log.Trace().Msg("scheduling")
			}
			lines = lines[:0]
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
