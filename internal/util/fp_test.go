package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRepeat(t *testing.T) {
	assert.Equal(t, []int{1, 1, 1, 1, 1}, Repeat(1, 5))
	assert.Equal(t, []string{"-", "-", "-", "-", "-"}, Repeat("-", 5))
}

func TestMap(t *testing.T) {
	arr := []int{1, 2, 3, 4}
	assert.Equal(t, []int{2, 4, 6, 8}, Map(func(i int) int {
		return 2 * i
	}, arr))
}

func TestMapWith(t *testing.T) {
	arr := []int{1, 2, 3, 4}
	assert.Equal(t, []int{2, 4, 6, 8}, MapWith(func(i int) int {
		return 2 * i
	})(arr))
}

func TestAtoi(t *testing.T) {
	assert.Equal(t, 1, Atoi("1"))
	assert.Equal(t, 0, Atoi("Nan"))
}

func TestReduce(t *testing.T) {
	arr := []int{1, 2, 3, 4}
	assert.Equal(t, 10, Reduce(AddInt, 0, arr))
}

func TestReduceWith(t *testing.T) {
	arr := []int{1, 2, 3, 4}
	assert.Equal(t, 10, ReduceWith(AddInt)(0, arr))
}
