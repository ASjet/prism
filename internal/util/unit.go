package util

import "fmt"

var (
	sizeUnits = []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
)

func ReadableSize(bytes uint64) string {
	_size := float64(bytes)
	unitLevel := 0
	for bytes >= 1024 {
		bytes >>= 10
		_size /= 1024
		unitLevel++
	}
	if unitLevel == 0 {
		return fmt.Sprintf("%d%s", bytes, sizeUnits[unitLevel])
	}
	return fmt.Sprintf("%.2f%s", _size, sizeUnits[unitLevel])
}
