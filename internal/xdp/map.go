package xdp

import (
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

// The key and value size in ebpf map must be 8
func ReadCountMap[K comparable](m *ebpf.Map, keyParser func([]byte) K) (map[K]uint64, error) {
	if typ := m.Type(); typ != ebpf.Hash && typ != ebpf.PerCPUHash {
		return nil, errors.Errorf("expected map type Hash(1) or PerCPUHash(5), got %s", m.Type())
	}

	if m.KeySize() != 8 {
		return nil, errors.Errorf("expected key size to be 8, got %d", m.KeySize())
	}

	if m.ValueSize() != 8 {
		return nil, errors.Errorf("expected value size to be 8, got %d", m.ValueSize())
	}

	result := make(map[K]uint64)
	iter := m.Iterate()
	key := make([]byte, 8)
	value := make([]byte, 8)
	for iter.Next(&key, &value) {
		result[keyParser(key)] += binary.LittleEndian.Uint64(value)
	}
	return result, nil
}

func Get[K, V comparable](m map[K]V, key K, defaultValue V) V {
	if value, ok := m[key]; ok {
		return value
	}
	return defaultValue
}

type ProtoBase struct {
	L2 uint8
	L4 uint8
	L3 uint16
}

func ParseProtoBase(key []byte) ProtoBase {
	return ProtoBase{
		L2: key[0],
		L4: key[1],
		L3: binary.LittleEndian.Uint16(key[2:4]),
	}
}

func (p *ProtoBase) Layers() []string {
	layers := make([]string, 3)
	if p.L2 != 0 {
		layers[0] = "L2"
	}
	if p.L3 != 0 {
		layers[1] = "L3"
	}
	if p.L4 != 0 {
		layers[2] = "L4"
	}
	return layers
}

func (p *ProtoBase) Protocols() []string {
	return []string{
		Get(l2Proto, p.L2, "Other"),
		Get(l3Proto, p.L3, "Other"),
		Get(l4Proto, p.L4, "Other"),
	}
}

type ProtoKey struct {
	ProtoBase
	TopProtoType uint32
}

func ParseProtoKey(key []byte) ProtoKey {
	return ProtoKey{
		ProtoBase:    ParseProtoBase(key[0:4]),
		TopProtoType: binary.LittleEndian.Uint32(key[4:8]),
	}
}

func (p *ProtoKey) Layers() []string {
	// TODO: parse top layer
	return p.ProtoBase.Layers()
}

func (p *ProtoKey) Protocols() []string {
	// TODO: parse top layer
	return p.ProtoBase.Protocols()
}

type AppProtoKey struct {
	ProtoBase
	UnderL7 uint16
	L7      uint16
}

func ParseAppProtoKey(key []byte) AppProtoKey {
	return AppProtoKey{
		ProtoBase: ParseProtoBase(key[0:4]),
		UnderL7:   binary.LittleEndian.Uint16(key[4:6]),
		L7:        binary.LittleEndian.Uint16(key[6:8]),
	}
}

func (p *AppProtoKey) Layers() []string {
	// TODO: parse top layer
	return p.ProtoBase.Layers()
}

func (p *AppProtoKey) Protocols() []string {
	// TODO: parse top layer
	return p.ProtoBase.Protocols()
}
