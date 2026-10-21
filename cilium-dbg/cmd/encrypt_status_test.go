// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const procTestFixtures = "fixtures/proc"

func TestGetXfrmStats(t *testing.T) {
	errCount, m, err := getXfrmStats(procTestFixtures)
	require.NoError(t, err)
	currentCount := int64(0)
	testCases := []struct {
		name string
		want int64
	}{
		{name: "XfrmInError", want: 2},
		{name: "XfrmInBufferError", want: 0},
		{name: "XfrmInHdrError", want: 0},
		{name: "XfrmInNoStates", want: 225479},
		{name: "XfrmInStateProtoError", want: 141222},
		{name: "XfrmInStateModeError", want: 0},
		{name: "XfrmInStateSeqError", want: 0},
		{name: "XfrmInStateExpired", want: 0},
		{name: "XfrmInStateMismatch", want: 0},
		{name: "XfrmInStateInvalid", want: 0},
		{name: "XfrmInTmplMismatch", want: 0},
		{name: "XfrmInNoPols", want: 203389},
		{name: "XfrmInPolBlock", want: 0},
		{name: "XfrmInPolError", want: 0},
		{name: "XfrmOutError", want: 0},
		{name: "XfrmOutBundleGenError", want: 0},
		{name: "XfrmOutBundleCheckError", want: 0},
		{name: "XfrmOutNoStates", want: 36162},
		{name: "XfrmOutStateProtoError", want: 1886},
		{name: "XfrmOutStateModeError", want: 0},
		{name: "XfrmOutStateSeqError", want: 0},
		{name: "XfrmOutStateExpired", want: 0},
		{name: "XfrmOutPolBlock", want: 0},
		{name: "XfrmOutPolDead", want: 0},
		{name: "XfrmOutPolError", want: 0},
		{name: "XfrmFwdHdrError", want: 0},
		{name: "XfrmOutStateInvalid", want: 0},
		{name: "XfrmAcquireError", want: 0},
	}
	for _, test := range testCases {
		got := m[test.name]
		require.Equal(t, test.want, got)
		currentCount += got
	}
	require.Equal(t, errCount, currentCount)
}
