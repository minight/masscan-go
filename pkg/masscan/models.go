package masscan

import (
	"fmt"
	"inet.af/netaddr"
	"math/rand"
)

type Port = uint16

type Dst struct {
	IP   netaddr.IP
	Port Port
}

func (d Dst) String() string {
	return fmt.Sprintf("%s:%d", d.IP.String(), d.Port)
}

func (d *Dst) Nil() bool {
	if d == nil {
		return true
	}
	return d.Port == 0 && d.IP.IsZero()
}

type ResultState int

const (
	ResultState_UNKNOWN ResultState = iota
	ResultState_OPEN
	ResultState_CLOSE
)

type Res struct {
	Dst   Dst
	State ResultState
}

type src struct {
	ip   netaddr.IP
	port Port
}

func (s src) String() string {
	return fmt.Sprintf("%s:%d", s.ip.String(), s.port)
}

func (s *src) Nil() bool {
	if s == nil {
		return true
	}
	return s.port == 0 && s.ip.IsZero()
}

// Targets contains one batch of ips and ports to scan
// we use this as a single batch to avoid having to block on receiving more
type Targets struct {
	IPs      []netaddr.IP
	Ports    []Port
	shuffled bool
}

func (t Targets) IsEmpty() bool {
	return len(t.IPs) == 0 && len(t.Ports) == 0
}

func (t Targets) MaxIdx() uint64 {
	return uint64(int64(len(t.IPs) * len(t.Ports)))
}

// Shuffle will randomize the order of the IPs and ports in the list
// This is an inplace 0 allocation shuffle, so can be used to reorder all
// of the packets sent to different hosts
func (t *Targets) Shuffle() {
	if t.shuffled {
		return
	}

	t.shuffled = true

	shuffler := rand.New(rand.NewSource(entropySeed))
	shuffler.Shuffle(len(t.IPs), func(i, j int) { t.IPs[i], t.IPs[j] = t.IPs[j], t.IPs[i] })

	shuffler = rand.New(rand.NewSource(entropySeed))
	shuffler.Shuffle(len(t.Ports), func(i, j int) { t.Ports[i], t.Ports[j] = t.Ports[j], t.Ports[i] })
}

// Get will return the corresponding Dst from the targets list
// based off the size. This will always return a valid value
// If the value exceeds MaxIdx, then it will loop around and restart
// from 0
// This ordering should yield a "random" ordering of the ports and hosts
// which should be a sufficient distribution to not dos any services
func (t Targets) Get(i uint64) Dst {
	if i > t.MaxIdx() {
		i = i % t.MaxIdx()
	}

	ipIdx := i % uint64(len(t.IPs))
	ipLoop := i / uint64(len(t.IPs))
	portIdx := (ipLoop + ipIdx) % uint64(len(t.Ports))
	return Dst{
		IP:   t.IPs[ipIdx],
		Port: t.Ports[portIdx],
	}
}
