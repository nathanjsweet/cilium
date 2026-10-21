// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func xfrmStateMsg(reqID uint32, attrs ...[]byte) []byte {
	info := &nl.XfrmUsersaInfo{Reqid: reqID}
	msg := info.Serialize()
	for _, a := range attrs {
		msg = append(msg, a...)
	}
	return msg
}

// esnPayload returns a struct xfrm_replay_esn with a bmpLen word bitmap.
func esnPayload(oseq, oseqHi uint32, bmpLen int) []byte {
	// bmp_len, oseq, seq, oseq_hi, seq_hi, replay_window, bitmap.
	b := make([]byte, 0, nl.SizeofXfrmReplayStateEsn+4*bmpLen)
	for _, v := range []uint32{uint32(bmpLen), oseq, 0, oseqHi, 0, uint32(bmpLen * 32)} {
		b = append(b, nl.Uint32Attr(v)...)
	}
	return append(b, make([]byte, 4*bmpLen)...)
}

func esnAttr(oseq, oseqHi uint32) []byte {
	return nl.NewRtAttr(nl.XFRMA_REPLAY_ESN_VAL, esnPayload(oseq, oseqHi, 1)).Serialize()
}

func replayAttr(oseq uint32) []byte {
	st := &nl.XfrmReplayState{OSeq: oseq}
	return nl.NewRtAttr(nl.XFRMA_REPLAY_VAL, st.Serialize()).Serialize()
}

func TestParseXfrmOutputSeq(t *testing.T) {
	tests := []struct {
		name   string
		msg    []byte
		want   uint64
		wantOK bool
		errStr string
	}{
		{name: "esn", msg: xfrmStateMsg(1, esnAttr(0x13e0, 0)), want: 0x13e0, wantOK: true},
		{name: "esn with high bits", msg: xfrmStateMsg(1, esnAttr(0x5, 0x2)), want: 0x2_0000_0005, wantOK: true},
		{name: "legacy replay", msg: xfrmStateMsg(1, replayAttr(0xc3)), want: 0xc3, wantOK: true},
		{name: "other reqid", msg: xfrmStateMsg(2, esnAttr(0x13e0, 0))},
		{name: "no replay attr", msg: xfrmStateMsg(1)},
		{name: "short message", msg: []byte{1, 2, 3}, errStr: "short xfrm state message"},
		{
			name:   "short esn attribute",
			msg:    xfrmStateMsg(1, nl.NewRtAttr(nl.XFRMA_REPLAY_ESN_VAL, []byte{1, 2, 3, 4}).Serialize()),
			errStr: "short xfrm replay ESN attribute",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := parseXfrmOutputSeq(tc.msg, 1)
			if tc.errStr != "" {
				require.ErrorContains(t, err, tc.errStr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.want, got)
		})
	}
}

// rawRequestData lets a pre-serialized message header be added to a netlink
// request in order with its attributes. NetlinkRequest.AddRawData would place
// it after them.
type rawRequestData []byte

func (r rawRequestData) Len() int          { return len(r) }
func (r rawRequestData) Serialize() []byte { return r }

// setOutputSeq overwrites the output sequence numbers of an ESN state, like
// the kernel would advance them while encrypting packets (XFRM_MSG_NEWAE).
func setOutputSeq(t *testing.T, state *netlink.XfrmState, oseq, oseqHi uint32) {
	t.Helper()

	id := &nl.XfrmUsersaId{
		Spi:    nl.Swap32(uint32(state.Spi)),
		Family: uint16(nl.GetIPFamily(state.Dst)),
		Proto:  uint8(state.Proto),
	}
	id.Daddr.FromIP(state.Dst)

	// struct xfrm_aevent_id: sa_id, saddr, flags, reqid.
	aevent := id.Serialize()
	aevent = append(aevent, make([]byte, 16)...)
	aevent = append(aevent, nl.Uint32Attr(0)...)
	aevent = append(aevent, nl.Uint32Attr(uint32(state.Reqid))...)

	req := nl.NewNetlinkRequest(nl.XFRM_MSG_NEWAE, unix.NLM_F_REPLACE|unix.NLM_F_ACK)
	req.AddData(rawRequestData(aevent))
	// The kernel requires the attribute to match the length of the state's bitmap.
	req.AddData(nl.NewRtAttr(nl.XFRMA_REPLAY_ESN_VAL, esnPayload(oseq, oseqHi, state.ReplayWindow/32)))
	_, err := req.Execute(unix.NETLINK_XFRM, 0)
	require.NoError(t, err)
}

func TestPrivilegedMaxSequenceNumber(t *testing.T) {
	testutils.PrivilegedTest(t)

	newState := func(spi, reqID int) *netlink.XfrmState {
		return &netlink.XfrmState{
			Src:          net.ParseIP("192.0.2.1"),
			Dst:          net.ParseIP("192.0.2.2"),
			Proto:        netlink.XFRM_PROTO_ESP,
			Mode:         netlink.XFRM_MODE_TUNNEL,
			Spi:          spi,
			Reqid:        reqID,
			ESN:          true,
			ReplayWindow: 32,
			Aead: &netlink.XfrmStateAlgo{
				Name:   "rfc4106(gcm(aes))",
				Key:    make([]byte, 20),
				ICVLen: 128,
			},
		}
	}

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		// No state at all.
		got, err := maxSequenceNumber()
		require.NoError(t, err)
		require.Equal(t, "N/A", got)

		cilium1, cilium2, other := newState(1, 1), newState(2, 1), newState(3, 2)
		for _, s := range []*netlink.XfrmState{cilium1, cilium2, other} {
			// There is no xfrmStateCache to keep in sync in this isolated netns.
			//nolint:forbidigo
			require.NoError(t, netlink.XfrmStateAdd(s))
		}

		// Fresh states have not sent anything yet.
		got, err = maxSequenceNumber()
		require.NoError(t, err)
		require.Equal(t, "N/A", got)

		// The state of another reqid must be ignored, even if it has the
		// highest sequence number.
		setOutputSeq(t, cilium1, 0x10, 0)
		setOutputSeq(t, cilium2, 0x20, 0)
		setOutputSeq(t, other, 0x30, 0x7)

		seqs, err := xfrmStateOutputSeqs(1)
		require.NoError(t, err)
		require.ElementsMatch(t, []uint64{0x10, 0x20}, seqs)

		got, err = maxSequenceNumber()
		require.NoError(t, err)
		require.Equal(t, "0x20/0xffffffffffffffff", got)

		// The upper half of the ESN counter is part of the value.
		setOutputSeq(t, cilium1, 0x5, 0x1)

		got, err = maxSequenceNumber()
		require.NoError(t, err)
		require.Equal(t, "0x100000005/0xffffffffffffffff", got)
		return nil
	}))
}
