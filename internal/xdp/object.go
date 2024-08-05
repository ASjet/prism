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
	Prog   *ebpf.Program `ebpf:"prism"`
	CntMap *ebpf.Map     `ebpf:"prism_cnt"`
}

type XDP struct {
	obj  *prismObj
	spec *ebpf.CollectionSpec
	l    link.Link
}

func (x *XDP) CountMap() (map[ProtoKey]CountValue, error) {
	return ReadCountMap(x.obj.CntMap, ParseProtoKey, ParseCountValue)
}

func (x *XDP) Close() {
	x.l.Close()
	x.obj.Prog.Close()
	x.obj.CntMap.Close()
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
