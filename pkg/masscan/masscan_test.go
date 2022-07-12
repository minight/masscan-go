package masscan

import (
	"github.com/minight/masscan-go/pkg/log"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"inet.af/netaddr"
	"testing"
)

func Test_buildcookie(t *testing.T) {
	src := src{tup: tup{ip: netaddr.IPFrom4([4]byte{127, 0, 0, 1}), port: 443}}
	dst := Dst{tup: tup{ip: netaddr.IPFrom4([4]byte{192, 168, 68, 101}), port: 80}}
	buf2 := [36]byte{}
	buf1 := buildcookie(src, dst, nil)
	buildcookie2(src, dst, buf2[:])
	assert.Equal(t, buf1, buf2[:])
}

var result []byte

func BenchmarkBuildCookie1(b *testing.B) {
	buf := make([]byte, 0, 36)
	src := src{tup: tup{ip: netaddr.IPFrom4([4]byte{127, 0, 0, 1}), port: 443}}
	dst := Dst{tup: tup{ip: netaddr.IPFrom4([4]byte{192, 168, 68, 101}), port: 80}}
	for i := 0; i < b.N; i++ {
		buf = buildcookie(src, dst, buf)
		buf = buf[:0]
	}
	result = buf
}

func BenchmarkBuildCookie2(b *testing.B) {
	buf2 := [36]byte{}
	src := src{tup: tup{ip: netaddr.IPFrom4([4]byte{127, 0, 0, 1}), port: 443}}
	dst := Dst{tup: tup{ip: netaddr.IPFrom4([4]byte{192, 168, 68, 101}), port: 80}}
	for i := 0; i < b.N; i++ {
		buildcookie2(src, dst, buf2[:])
	}
	result = buf2[:]
}

func Test_newClient(t *testing.T) {
	_, err := New("en0", log.TestLogger(t, zerolog.InfoLevel))
	assert.Nil(t, err)
}

func TestTargets_Get(t1 *testing.T) {
	type fields struct {
		IPs   []netaddr.IP
		Ports []Port
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{
		{"matching ports, ips",
			fields{
				IPs: []netaddr.IP{
					netaddr.MustParseIP("1.1.1.1"),
					netaddr.MustParseIP("2.2.2.2"),
					netaddr.MustParseIP("3.3.3.3"),
					netaddr.MustParseIP("4.4.4.4"),
				},
				Ports: []Port{80, 443, 8080, 8443},
			},
			[]string{
				"1.1.1.1:80", "2.2.2.2:443", "3.3.3.3:8080", "4.4.4.4:8443",
				"1.1.1.1:443", "2.2.2.2:8080", "3.3.3.3:8443", "4.4.4.4:80",
				"1.1.1.1:8080", "2.2.2.2:8443", "3.3.3.3:80", "4.4.4.4:443",
				"1.1.1.1:8443", "2.2.2.2:80", "3.3.3.3:443", "4.4.4.4:8080",
			},
			// 1 2 3 4
			// 2 3 4 5
			// 3 4 5 6
			// 4 5 6 7
		},
		{"more ips than ports",
			fields{
				IPs: []netaddr.IP{
					netaddr.MustParseIP("1.1.1.1"),
					netaddr.MustParseIP("2.2.2.2"),
					netaddr.MustParseIP("3.3.3.3"),
					netaddr.MustParseIP("4.4.4.4"),
				},
				Ports: []Port{80, 443, 8080},
			},
			[]string{
				"1.1.1.1:80", "2.2.2.2:443", "3.3.3.3:8080", "4.4.4.4:80",
				"1.1.1.1:443", "2.2.2.2:8080", "3.3.3.3:80", "4.4.4.4:443",
				"1.1.1.1:8080", "2.2.2.2:80", "3.3.3.3:443", "4.4.4.4:8080",
			},
		},
		{"diff offset ports, ips",
			fields{
				IPs: []netaddr.IP{
					netaddr.MustParseIP("1.1.1.1"),
					netaddr.MustParseIP("2.2.2.2"),
					netaddr.MustParseIP("3.3.3.3"),
				},
				Ports: []Port{80, 443, 8080, 8443},
			},
			[]string{
				"1.1.1.1:80", "2.2.2.2:443", "3.3.3.3:8080",
				"1.1.1.1:443", "2.2.2.2:8080", "3.3.3.3:8443",
				"1.1.1.1:8080", "2.2.2.2:8443", "3.3.3.3:80",
				"1.1.1.1:8443", "2.2.2.2:80", "3.3.3.3:443",
			},
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			in := Targets{
				IPs:   tt.fields.IPs,
				Ports: tt.fields.Ports,
			}
			var i uint64
			res := make([]string, 0)
			for i = 0; i < in.MaxIdx(); i++ {
				res = append(res, in.Get(i).String())
			}

			assert.ElementsMatch(t1, tt.want, res)
		})
	}
}
