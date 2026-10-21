// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/binary"
	"fmt"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

// sizeofReplayStateEsnHdr is the size of the fixed part of struct
// xfrm_replay_esn (bmp_len, oseq, seq, oseq_hi, seq_hi, replay_window),
// which precedes the variable-length replay bitmap.
const sizeofReplayStateEsnHdr = nl.SizeofXfrmReplayStateEsn

// xfrmStateOutputSeqs dumps all XFRM states and returns, for each one whose
// reqid matches, its 64-bit output sequence number.
//
// vishvananda/netlink only decodes XFRMA_REPLAY_VAL into XfrmState.Replay and
// ignores XFRMA_REPLAY_ESN_VAL. Cilium installs its states with ESN enabled,
// for which the kernel reports the sequence numbers only in the latter
// attribute, so the raw dump has to be decoded here.
func xfrmStateOutputSeqs(reqID int) ([]uint64, error) {
	msgs, err := safenetlink.WithRetryResult(func() ([][]byte, error) {
		req := nl.NewNetlinkRequest(nl.XFRM_MSG_GETSA, unix.NLM_F_DUMP)
		return req.Execute(unix.NETLINK_XFRM, nl.XFRM_MSG_NEWSA)
	})
	if err != nil {
		return nil, fmt.Errorf("cannot dump xfrm states: %w", err)
	}

	var seqs []uint64
	for _, m := range msgs {
		seq, ok, err := parseXfrmOutputSeq(m, reqID)
		if err != nil {
			return nil, err
		}
		if ok {
			seqs = append(seqs, seq)
		}
	}
	return seqs, nil
}

// parseXfrmOutputSeq decodes one XFRM_MSG_NEWSA message. ok is false if the
// state does not belong to reqID or does not carry any replay state.
func parseXfrmOutputSeq(m []byte, reqID int) (seq uint64, ok bool, err error) {
	if len(m) < nl.SizeofXfrmUsersaInfo {
		return 0, false, fmt.Errorf("short xfrm state message: %d bytes", len(m))
	}
	if int(nl.DeserializeXfrmUsersaInfo(m).Reqid) != reqID {
		return 0, false, nil
	}

	attrs, err := nl.ParseRouteAttr(m[nl.SizeofXfrmUsersaInfo:])
	if err != nil {
		return 0, false, fmt.Errorf("cannot parse xfrm state attributes: %w", err)
	}
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case nl.XFRMA_REPLAY_ESN_VAL:
			if len(attr.Value) < sizeofReplayStateEsnHdr {
				return 0, false, fmt.Errorf("short xfrm replay ESN attribute: %d bytes", len(attr.Value))
			}
			// Layout: bmp_len, oseq, seq, oseq_hi, seq_hi, replay_window.
			oseq := binary.NativeEndian.Uint32(attr.Value[4:8])
			oseqHi := binary.NativeEndian.Uint32(attr.Value[12:16])
			return uint64(oseqHi)<<32 | uint64(oseq), true, nil
		case nl.XFRMA_REPLAY_VAL:
			if len(attr.Value) < nl.SizeofXfrmReplayState {
				return 0, false, fmt.Errorf("short xfrm replay attribute: %d bytes", len(attr.Value))
			}
			return uint64(nl.DeserializeXfrmReplayState(attr.Value).OSeq), true, nil
		}
	}
	return 0, false, nil
}
