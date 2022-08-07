package cmd

import (
	"reflect"
	"testing"

	"github.com/minight/masscan-go/pkg/masscan"
	"github.com/rs/zerolog"
	"inet.af/netaddr"
)

func TestPrepareDst(t *testing.T) {
	type args struct {
		in        []string
		ports     []uint16
		chunkSize int
	}
	tests := []struct {
		name    string
		args    args
		wantRet []masscan.Targets
	}{
		{
			name: "simple",
			args: args{
				in:        []string{"1.1.1.1"},
				ports:     []uint16{80},
				chunkSize: 2,
			},
			wantRet: []masscan.Targets{{
				IPs:   []netaddr.IP{netaddr.MustParseIP("1.1.1.1")},
				Ports: []masscan.Port{80},
			}},
		},
		{
			name: "simple cidr",
			args: args{
				in:        []string{"1.1.1.1/32"},
				ports:     []uint16{80},
				chunkSize: 2,
			},
			wantRet: []masscan.Targets{{
				IPs:   []netaddr.IP{netaddr.MustParseIP("1.1.1.1")},
				Ports: []masscan.Port{80},
			}},
		},
		{
			name: "simple cidr multiple ips",
			args: args{
				in:        []string{"1.1.1.1/31"},
				ports:     []uint16{80},
				chunkSize: 2,
			},
			wantRet: []masscan.Targets{{
				IPs:   []netaddr.IP{netaddr.MustParseIP("1.1.1.0"), netaddr.MustParseIP("1.1.1.1")},
				Ports: []masscan.Port{80},
			}},
		},
		{
			name: "chunked cidr multiple ips",
			args: args{
				in:        []string{"1.1.1.1/30"},
				ports:     []uint16{80},
				chunkSize: 2,
			},
			wantRet: []masscan.Targets{
				{
					IPs:   []netaddr.IP{netaddr.MustParseIP("1.1.1.0"), netaddr.MustParseIP("1.1.1.1")},
					Ports: []masscan.Port{80},
				},
				{
					IPs:   []netaddr.IP{netaddr.MustParseIP("1.1.1.2"), netaddr.MustParseIP("1.1.1.3")},
					Ports: []masscan.Port{80},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotRet := PrepareDst(zerolog.New(zerolog.NewTestWriter(t)), tt.args.in, tt.args.ports, tt.args.chunkSize); !reflect.DeepEqual(gotRet, tt.wantRet) {
				t.Errorf("PrepareDst() = %v, want %v", gotRet, tt.wantRet)
			}
		})
	}
}
