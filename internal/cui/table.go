package cui

import (
	"fmt"
	"sort"

	"github.com/ASjet/prism/internal/util"
	"github.com/ASjet/prism/internal/xdp"
	"github.com/jedib0t/go-pretty/v6/table"
)

var (
	rowConfigAutoMerge = table.RowConfig{AutoMerge: true}
)

type Entry struct {
	Protocols []string
	Packets   uint64
	Bytes     uint64
}

type Entries []*Entry

func (e Entries) Len() int {
	return len(e)
}

// Sort the [][]string
func (e Entries) Less(i, j int) bool {
	if len(e[i].Protocols) != len(e[j].Protocols) {
		panic("different length of protocols")
	}
	for k := range e[i].Protocols {
		if e[i].Protocols[k] != e[j].Protocols[k] {
			return e[i].Protocols[k] < e[j].Protocols[k]
		}
	}
	return false
}

func (e Entries) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

func Render(pktMap, byteMap map[xdp.ProtoKey]uint64) string {
	t := table.NewWriter()
	toInterface := util.MapWith[string](util.ToInterface)
	headers := append(new(xdp.ProtoKey).Layers(), "Packets", "Bytes", "Percentage")
	t.AppendHeader(table.Row(toInterface(headers)))

	entries := make(Entries, 0, len(pktMap))
	for k, v := range pktMap {
		entries = append(entries, &Entry{
			Protocols: k.Protocols(),
			Packets:   v,
			Bytes:     byteMap[k],
		})
	}

	sort.Sort(entries)

	pktSum := util.Reduce(util.AddUint64, 0, util.Map(func(entry *Entry) uint64 {
		return entry.Packets
	}, entries))
	byteSum := util.Reduce(util.AddUint64, 0, util.Map(func(entry *Entry) uint64 {
		return entry.Bytes
	}, entries))

	for i := range entries {
		pkt := entries[i].Packets
		bs := entries[i].Bytes
		row := append(table.Row(toInterface(entries[i].Protocols)),
			pkt,
			util.ReadableSize(bs),
			calPercentage(pkt, pktSum),
		)
		t.AppendRow(row, rowConfigAutoMerge)
	}

	footer := append(table.Row(toInterface(util.Repeat("Total", len(headers)-3))),
		pktSum, util.ReadableSize(byteSum), "100%")

	t.AppendFooter(footer, rowConfigAutoMerge)
	t.SetAutoIndex(false)
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
		{Number: 2, AutoMerge: true},
		{Number: 3, AutoMerge: true},
		{Number: 4, AutoMerge: true},
	})
	t.SetStyle(table.StyleLight)
	t.Style().Options.SeparateRows = true

	return t.Render()
}

func calPercentage(a, b uint64) string {
	if b == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.2f%%", float64(a)/float64(b)*100)
}
