package xdp

import (
	"io"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
)

const (
	LoadModeGeneric = "generic"
	LoadModeDriver  = "native"
	LoadModeOffload = "hw"
)

type prismObj struct {
	Prog       *ebpf.Program `ebpf:"prism"`
	PktCntMap  *ebpf.Map     `ebpf:"prism_pkt_cnt"`
	ByteCntMap *ebpf.Map     `ebpf:"prism_byte_cnt"`
}

type XDP struct {
	obj  *prismObj
	spec *ebpf.CollectionSpec
	l    link.Link
}

func (x *XDP) PktCountMap() (map[ProtoKey]uint64, error) {
	return ReadCountMap(x.obj.PktCntMap, ParseProtoKey)
}

func (x *XDP) ByteCountMap() (map[ProtoKey]uint64, error) {
	return ReadCountMap(x.obj.ByteCntMap, ParseProtoKey)
}

func (x *XDP) Close() {
	x.l.Close()
	x.obj.Prog.Close()
	x.obj.PktCntMap.Close()
	x.obj.ByteCntMap.Close()
}

func LoadAndAttach(nic string, prog io.ReaderAt, mode string) (*XDP, error) {
	iface, err := net.InterfaceByName(nic)
	if err != nil {
		return nil, errors.Wrap(err, "get nic interface error")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(prog)
	if err != nil {
		return nil, errors.Wrap(err, "load xdp program error")
	}

	obj := new(prismObj)
	if err := spec.LoadAndAssign(obj, nil); err != nil {
		return nil, errors.Wrap(err, "load and assign xdp object error")
	}

	var flag link.XDPAttachFlags
	switch mode {
	case LoadModeGeneric:
		flag = link.XDPGenericMode
	case LoadModeDriver:
		flag = link.XDPDriverMode
	case LoadModeOffload:
		flag = link.XDPOffloadMode
	default:
		flag = 0
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.Prog,
		Interface: iface.Index,
		Flags:     flag,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "attach xdp program to interface %s error", nic)
	}
	return &XDP{
		obj:  obj,
		spec: spec,
		l:    l,
	}, nil
}
