package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseKeyDID(t *testing.T) {
	_, err := ParseKeyDID("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
	if !assert.NoError(t, err) {
		return
	}
}
