package masscan

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dchest/siphash"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"go.uber.org/ratelimit"
	"inet.af/netaddr"
)

const (
	// we use cloudflare as our default attempt to get an ARP response
	arpDst4 = "1.1.1.1"
	arpDst6 = "2606:4700:4700::1111"

	entropySeed = 1
)

func buildcookie(src src, dst Dst, buf []byte) []byte {
	srcip := src.ip.As16()
	buf = append(buf, srcip[:]...)

	tmp := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp, src.port)
	buf = append(buf, tmp...)

	dstip := dst.IP.As16()
	buf = append(buf, dstip[:]...)
	binary.LittleEndian.PutUint16(tmp, dst.Port)
	buf = append(buf, tmp...)
	return buf
}

// buildcookie2 will construct the cookie using a direct write to the buffer memory
// this assumes the input buffer is of sufficient length
func buildcookie2(src src, dst Dst, buf []byte) {
	if len(buf) < 36 {
		return
	}
	srcip := src.ip.As16()
	copy(buf[0:16], srcip[:])
	binary.LittleEndian.PutUint16(buf[16:18], src.port)

	dstip := dst.IP.As16()
	copy(buf[18:34], dstip[:])
	binary.LittleEndian.PutUint16(buf[34:36], dst.Port)
}

type SynCookie uint64

func SynCookieV4(src src, dst Dst, seed uint64) SynCookie {
	var data [36]byte
	buildcookie2(src, dst, data[:])
	sum64 := siphash.Hash(seed, seed, data[:])
	return SynCookie(sum64)
}

func (c *Client) AppendPacket(src src, dst Dst, cookie SynCookie) {
	ip4 := &layers.IPv4{
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    src.ip.IPAddr().IP,
		DstIP:    dst.IP.IPAddr().IP,
		Version:  4,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(src.port),
		DstPort: layers.TCPPort(dst.Port),
		SYN:     true,
		Seq:     uint32(cookie),
	}

	c.Log.Trace().
		Str("srcMAC", c.srcMAC.String()).
		Str("dstMAC", c.dstMAC.String()).
		Uint16("srcPort", src.port).
		Uint16("dstPort", dst.Port).
		Str("srcIP", src.ip.String()).
		Str("dstIP", dst.IP.String()).
		Msg("sending packet")

	tcp.SetNetworkLayerForChecksum(ip4)
	gopacket.SerializeLayers(c.buf, c.opts,
		&layers.Ethernet{
			SrcMAC:       c.srcMAC,
			DstMAC:       c.dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		ip4,
		tcp,
	)
}

type Client struct {
	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	// Dst, gw, src net.IP

	handle     *pcap.Handle
	handleName string

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer

	src src

	srcMAC, dstMAC net.HardwareAddr

	ratelimit ratelimit.Limiter

	cache *ttlcache.Cache[Dst, bool]

	// retries is the number of times to send a packet, can be 0.
	// we don't actually track if we've sent a packet before or whether we should retry
	// we just employ the masscan strategy of shooting everything off N times, then tracking
	// duplicate responses
	retries int

	Log zerolog.Logger
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
// we shameless "borrow" this code from gopacket/examples/synscan/main.go
func (c *Client) getHwAddr() (srcIP net.IP, src net.HardwareAddr, dst net.HardwareAddr, err error) {
	start := time.Now()
	// we do a fixed lookup for some random IP address. This should hopefully respond. i have no idea
	// Prepare the layers to send for an ARP request.
	srcMac, err := net.InterfaceByName(c.handleName)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to get hardware addr")
	}
	srcAddrs, err := srcMac.Addrs()
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to get hardware IP")
	}

	if len(srcAddrs) == 0 {
		return nil, nil, nil, errors.New("no hardware addrs found")
	}

	c.Log.Debug().
		Msgf("src addrs: %+v", srcAddrs)
	var (
		arpDstAddr, srcAddr string
		srcAddrByte         net.IP
		ip4Ifaces           []net.IP
		ip6Ifaces           []net.IP
	)

	for _, v := range srcAddrs {
		srcAddr = v.String()
		c.Log.Trace().Str("addr", v.String()).Msg("found iface")
		if strings.ContainsAny(v.String(), ":") {
			// skip ip6 for now to get it working on ip4
			ip6Ifaces = append(ip6Ifaces, v.(*net.IPNet).IP)
		} else {
			arpDstAddr = arpDst4
			ip4Ifaces = append(ip4Ifaces, v.(*net.IPNet).IP)
		}
	}
	if len(ip4Ifaces) == 0 {
		// this is where we have no ip4 addresess and only ip6. so just pick ip6
		// TODO: handle ip4 and ip6 separately with two separate listeners
		// this must mean that there is at least 1 ip6 addr
		// so we'll pick the first one
		srcAddrByte = ip6Ifaces[0]
		arpDstAddr = arpDst6
		c.Log.Info().Str("addr", srcAddrByte.String()).Msg("no ip4 ifaces, so we'll pick ip6")
	} else {
		srcAddrByte = ip4Ifaces[0]
		arpDstAddr = arpDst4
		c.Log.Info().Str("addr", srcAddrByte.String()).Msg("selected iface")
	}

	// remove the cidr
	srcAddr, _, _ = strings.Cut(srcAddr, "/")

	dstAddrIP, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to get gateway addr")
	}
	arpDstAddr = dstAddrIP.String()

	c.Log.Trace().
		Str("srcMAC", srcMac.HardwareAddr.String()).
		Str("srcProt", srcAddr).
		Bytes("srcProtByte", srcAddrByte.To4()).
		Bytes("srcProtIPByte", srcAddrByte).
		Bytes("dstProtByte", dstAddrIP.To4()).
		Str("dstProt", arpDstAddr).
		Msg("sending ARP request")

	eth := layers.Ethernet{
		SrcMAC:       srcMac.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMac.HardwareAddr),
		SourceProtAddress: srcAddrByte.To4(),
		// SourceProtAddress: dstAddrIP.To4(),
		DstHwAddress:   []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress: dstAddrIP.To4(),
	}
	// Send a single ARP request packet (we never retry a send, since this
	// is just an example ;)
	// TODO: optimize this to make arp with retries
	if err := c.send(&eth, &arp); err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to send arp req")
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, nil, nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := c.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, nil, nil, errors.Wrap(err, "failed to read packet data")
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			c.Log.Trace().
				Bytes("srcMAC", arp.SourceHwAddress).
				Bytes("dstMAC", arp.DstHwAddress).
				Bytes("arpDstAddr", arp.DstProtAddress).
				Bytes("arpSrcAddr", arp.SourceProtAddress).
				Msg("received arp request")
			if net.IP(arp.SourceProtAddress).Equal(dstAddrIP.To4()) {
				return srcAddrByte, srcMac.HardwareAddr, arp.SourceHwAddress, nil
			}
		}
	}
}

// send sends the given layers as a single packet on the network.
func (c *Client) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(c.buf, c.opts, l...); err != nil {
		return err
	}
	return c.handle.WritePacketData(c.buf.Bytes())
}

func New(iface string, log zerolog.Logger, rate int, retries int) (*Client, error) {
	sublog := log.With().
		Str("ctx", "clientInit").
		Logger()

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, errors.Wrap(err, "failed to find devices")
	}

	var pcapiface pcap.Interface
	var found bool
	for _, dv := range devices {
		sublog.Debug().
			Str("device", dv.Name).
			Msg("devices")

		if dv.Name == iface {
			pcapiface = dv
			found = true
			break
		}
	}
	if !found {
		return nil, errors.Wrap(err, "unable to find device")
	}

	if len(pcapiface.Addresses) == 0 {
		return nil, errors.Wrap(err, "iface selected has no addresses")
	}

	var (
		snapshot_len int32         = 65536
		promiscuous  bool          = true
		timeout      time.Duration = pcap.BlockForever
		dev                        = pcapiface.Name
		// srcIP                      = pcapiface.Addresses[0].IP
		handle *pcap.Handle
	)
	handle, err = pcap.OpenLive(
		dev,
		snapshot_len,
		promiscuous,
		timeout,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open pcap")
	}

	c := &Client{
		handle:     handle,
		handleName: dev,
		// src:        srcIP,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
		src: src{
			port: 42069,
		},
		cache: ttlcache.New[Dst, bool](
			ttlcache.WithCapacity[Dst, bool](10000),
		),
		retries: retries,
		Log:     log.With().Str("ctx", "masscan").Logger(),
	}
	var tmpip net.IP
	tmpip, c.srcMAC, c.dstMAC, err = c.getHwAddr()
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve hw addr")
	}

	c.src.ip, _ = netaddr.FromStdIP(tmpip)

	if rate == 0 {
		c.ratelimit = ratelimit.NewUnlimited()
	} else {
		c.ratelimit = ratelimit.New(rate, ratelimit.WithoutSlack)
	}

	return c, nil
}

func (c *Client) Close() error {
	c.handle.Close()
	return nil
}

// sender returns the packets sent and the age of the sender
func (c *Client) sender(ctx context.Context, in <-chan Targets) (sent int64, duration time.Duration) {
	start := time.Now()
	c.Log.Debug().
		Str("handle", c.handleName).
		Msg("sending on")

loop:
	for {
		select {
		case <-ctx.Done():
			return sent, time.Since(start)
		case tg, ok := <-in:
			if tg.IsEmpty() && !ok {
				break loop
			}
			// do a little shuffle before we shoot everything out so the order is a bit less predictable
			tg.Shuffle()
			var i uint64
			for i = 0; i < tg.MaxIdx()*uint64(1+c.retries); i++ {
				t := tg.Get(i)
				c.Log.Debug().
					Str("host", t.IP.String()).
					Uint16("Port", t.Port).
					Msg("sending")
				cookie := SynCookieV4(c.src, t, entropySeed)
				c.AppendPacket(c.src, t, cookie)

				wait := c.ratelimit.Take()
				sent++
				tmp := c.buf.Bytes()
				c.Log.Trace().
					Bytes("packet", tmp).
					Time("ratelimit", wait).
					Msg("writing data")
				if err := c.handle.WritePacketData(tmp); err != nil {
					c.Log.Error().
						Str("host", t.IP.String()).
						Uint16("Port", t.Port).
						Err(err).
						Msg("failed to write packet data")
				}
				if err := c.buf.Clear(); err != nil {
					c.Log.Error().
						Str("host", t.IP.String()).
						Uint16("Port", t.Port).
						Err(err).
						Msg("failed to clear the buffer")
				}
			}
		}
	}
	c.Log.Debug().Msg("exiting sender")

	return sent, time.Since(start)
}

func (c *Client) recver(ctx context.Context, out chan Res) (seen int64, age time.Duration) {
	start := time.Now()
	c.Log.Debug().
		Str("handle", c.handleName).
		Msg("recving on")

	var (
		eth layers.Ethernet
		ip4 layers.IPv4
		ip6 layers.IPv6
		tcp layers.TCP

		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)

		decodedLayers = make([]gopacket.LayerType, 0, 6)
	)

	for {
		select {
		case <-ctx.Done():
			return seen, time.Since(start)
		default:
			seen++
			data, _, err := c.handle.ReadPacketData()
			if err != nil {
				c.Log.Debug().Err(err).Msg("failed to get packet")
				continue
			}
			err = parser.DecodeLayers(data, &decodedLayers)
			if err != nil {
				c.Log.Trace().Err(err).Msg("failed to decode packet")
				// we don't continue here because we dont unmarshal the TLS layer
				// so we may end up getting tls data here that we don't want
			}
			// TODO: handle ip6
			var (
				ipMe, _   = netaddr.FromStdIP(ip4.DstIP)
				ipThem, _ = netaddr.FromStdIP(ip4.SrcIP)
				portMe    = tcp.DstPort
				portThem  = tcp.SrcPort
				me        = src{
					ip:   ipMe,
					port: uint16(portMe),
				}
				them = Dst{
					IP:   ipThem,
					Port: uint16(portThem),
				}
				// seqnoThem = tcp.Seq
				seqnoMe = tcp.Ack
				cookie  = SynCookieV4(me, them, entropySeed)
			)
			if me != c.src {
				c.Log.Trace().
					Str("me", me.String()).
					Str("them", them.String()).
					Msg("not our packet. non-matching src")
				continue
			}

			if uint32(cookie) != seqnoMe-1 {
				c.Log.Trace().
					Str("me", me.String()).
					Str("them", them.String()).
					Uint32("cookie", uint32(cookie)).
					Uint32("gotcookie", seqnoMe-1).
					Msg("failed to decode packet")
				continue
			}
			if c.cache.Get(them) != nil {
				continue
			}
			c.cache.Set(them, true, ttlcache.DefaultTTL)

			if tcp.SYN && tcp.ACK {
				out <- Res{
					Dst:   them,
					State: ResultState_OPEN,
				}
				c.Log.Debug().Str("them", them.String()).Msg("Port open")
				// In theory, we should send a RST packet here, but we actually just rely on the kernel to do
				// that for us. :p
				// yes in theory, it may be possible for us to have a whole lot of dangling connections if the kernel
				// doesn't do that, but in current observations, it seems like the kernel will automatically
				// RST packets that it doesnt expect, so we can rely on that behaviour on *nix systems.
				// Lol... shitty hacks
			} else if tcp.RST {
				c.Log.Debug().Str("them", them.String()).Msg("Port closed")
				out <- Res{
					Dst:   them,
					State: ResultState_CLOSE,
				}
			}
		}
	}
	return seen, time.Since(start)
}

// Run will initialize the threads needed for performing Port scanning. Inputs are expected to be provided
// using the input channel and results will be returned with the out channel.
// Run can be terminated by either closing the input channel, or by cancelling the context
// Closing the input channel will trigger a graceful termination where any inflight packets will be
// awaited for before closing the output channel
// Cancelling the context will trigger a non-graceful force shutdown of the worker
func Run(ctx context.Context, iface string, log zerolog.Logger, rate int, retries int) (chan<- Targets, <-chan Res, error) {
	ctx, cancel := context.WithCancel(ctx)
	log.Debug().Msg("starting")

	results := make(chan Res, 1000)
	in := make(chan Targets, 1000)

	c, err := New(iface, log, rate, retries)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create Client")
	}

	// TODO: expose a closable interface defer c.Close()
	// otherwise we just leak memory
	log.Debug().Msgf("Client initialized: %+v", c)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sent, age := c.sender(ctx, in)

		pps := int64(float64(sent) / age.Seconds())
		log.Info().
			Int64("packets_sent", sent).
			Dur("duration_seconds", age).
			Int64("pps", pps).
			Msg("packets send stats")

		log.Info().Msg("waiting 5s for timeouts")
		time.Sleep(5 * time.Second)
		cancel()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		recv, age := c.recver(ctx, results)

		pps := int64(float64(recv) / age.Seconds())
		log.Info().
			Int64("packets_recv", recv).
			Dur("duration_seconds", age).
			Int64("pps", pps).
			Msg("packet read stats")
		log.Debug().Msg("exiting recver")

		close(results)
	}()

	log.Debug().Msg("completing main loop")

	return in, results, nil
}
