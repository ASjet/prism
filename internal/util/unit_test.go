package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadableSize(t *testing.T) {
	tests := map[uint64]string{
		0:         "0B",
		1<<10 - 1: "1023B",
		1 << 10:   "1.00KiB",
		1 << 20:   "1.00MiB",
		1 << 30:   "1.00GiB",
		1 << 40:   "1.00TiB",
		1 << 50:   "1.00PiB",
		1 << 60:   "1.00EiB",
	}

	for unit, expect := range tests {
		assert.Equal(t, expect, ReadableSize(unit))
	}
}
