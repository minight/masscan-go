package cmd

import (
	"reflect"
	"testing"

	"github.com/rs/zerolog"
)

func TestPrepareDst(t *testing.T) {
	type args struct {
		log       zerolog.Logger
		in        []string
		ports     []uint16
		chunkSize int
	}
	tests := []struct {
		name    string
		args    args
		wantRet []masscan.Targets
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotRet := PrepareDst(tt.args.log, tt.args.in, tt.args.ports, tt.args.chunkSize); !reflect.DeepEqual(gotRet, tt.wantRet) {
				t.Errorf("PrepareDst() = %v, want %v", gotRet, tt.wantRet)
			}
		})
	}
}
