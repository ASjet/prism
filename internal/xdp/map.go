package xdp

import (
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

type Adder[T any] interface {
	Add(T) T
}

func ReadCountMap[K comparable, V any, A Adder[V]](
	m *ebpf.Map,
	keyParser func([]byte) K,
	valueParser func([]byte) A,
) (map[K]V, error) {
	if typ := m.Type(); typ != ebpf.Hash && typ != ebpf.PerCPUHash {
		return nil, errors.Errorf("expected map type Hash(1) or PerCPUHash(5), got %s", m.Type())
	}

	if keySize := binary.Size(*new(K)); m.KeySize() != uint32(keySize) {
		return nil, errors.Errorf("expected key size to be %d, got %d", keySize, m.KeySize())
	}

	if valueSize := binary.Size(*new(V)); m.ValueSize() != uint32(valueSize) {
		return nil, errors.Errorf("expected value size to be %d, got %d", valueSize, m.ValueSize())
	}

	result := make(map[K]V)
	iter := m.Iterate()
	key := make([]byte, int(m.KeySize()))

	switch m.Type() {
	case ebpf.Hash:
		value := make([]byte, int(m.ValueSize()))
		for iter.Next(&key, &value) {
			result[keyParser(key)] = valueParser(value).Add(result[keyParser(key)])
		}
	case ebpf.PerCPUHash:
		values := make([][]byte, ebpf.MustPossibleCPU())
		for i := range values {
			values[i] = make([]byte, int(m.ValueSize()))
		}
		for iter.Next(&key, &values) {
			for _, value := range values {
				result[keyParser(key)] = valueParser(value).Add(result[keyParser(key)])
			}
		}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func Get[K, V comparable](m map[K]V, key K, defaultValue V) V {
	if value, ok := m[key]; ok {
		return value
	}
	return defaultValue
}

type ProtoKey struct {
	L2           uint8
	L4           uint8
	L3           uint16
	L7           uint16
	TopProtoType uint16
}

func ParseProtoKey(key []byte) ProtoKey {
	return ProtoKey{
		L2: key[0],
		L4: key[1],
		L3: binary.LittleEndian.Uint16(key[2:4]),
	}
}

func (*ProtoKey) Layers() []string {
	return []string{"L2", "L3", "L4"}
}

func (p *ProtoKey) Protocols() []string {
	// TODO: parse l7 and topProtoType
	return []string{
		Get(l2Proto, p.L2, "Other"),
		Get(l3Proto, p.L3, "Other"),
		Get(l4Proto, p.L4, "Other"),
	}
}

type CountValue struct {
	ByteCnt uint64
	PktCnt  uint64
}

func ParseCountValue(value []byte) Adder[CountValue] {
	return CountValue{
		ByteCnt: binary.LittleEndian.Uint64(value[:8]),
		PktCnt:  binary.LittleEndian.Uint64(value[8:]),
	}
}

func (lhs CountValue) Add(rhs CountValue) CountValue {
	return CountValue{
		ByteCnt: lhs.ByteCnt + rhs.ByteCnt,
		PktCnt:  lhs.PktCnt + rhs.PktCnt,
	}
}
