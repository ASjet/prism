package util

import (
	"strconv"
)

func Repeat[T any](s T, n int) []T {
	result := make([]T, n)
	for i := range result {
		result[i] = s
	}
	return result
}

func Map[T, K any](mapper func(T) K, arr []T) []K {
	result := make([]K, len(arr))
	for i := range arr {
		result[i] = mapper(arr[i])
	}
	return result
}

func MapWith[T, K any](mapper func(T) K) func([]T) []K {
	return func(arr []T) []K {
		return Map(mapper, arr)
	}
}

func Atoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}

func ToInterface[T any](t T) interface{} {
	return t
}

func Reduce[T any](reducer func(T, T) T, cum T, arr []T) T {
	arrLen := len(arr)
	switch arrLen {
	case 0:
		return cum
	case 1:
		return arr[0]
	default:
		pivit := arrLen >> 1
		left, right := arr[:pivit], arr[pivit:]
		return reducer(Reduce(reducer, cum, left), Reduce(reducer, cum, right))
	}
}

func ReduceWith[T any](reducer func(T, T) T) func(T, []T) T {
	return func(cum T, arr []T) T {
		return Reduce(reducer, cum, arr)
	}
}

func AddInt(a, b int) int {
	return a + b
}

func AddUint64(a, b uint64) uint64 {
	return a + b
}