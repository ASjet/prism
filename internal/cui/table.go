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

func RenderTable(cntMap map[xdp.ProtoKey]xdp.CountValue, width, height int) string {
	t := table.NewWriter()
	toInterface := util.MapWith(func(s string) interface{} { return s })
	headers := append(new(xdp.ProtoKey).Layers(), "Packets", "Bytes", "Percentage")
	t.AppendHeader(table.Row(toInterface(headers)))
	t.SetAllowedRowLength(width)
	t.SetPageSize(height)

	entries := make(Entries, 0, len(cntMap))
	for k, v := range cntMap {
		entries = append(entries, &Entry{
			Protocols: k.Protocols(),
			Packets:   v.PktCnt,
			Bytes:     v.ByteCnt,
		})
	}

	sort.Sort(entries)

	sumUint64 := util.ReduceWith(func(a, b uint64) uint64 { return a + b })
	pktSum := sumUint64(0, util.Map(func(entry *Entry) uint64 {
		return entry.Packets
	}, entries))
	byteSum := sumUint64(0, util.Map(func(entry *Entry) uint64 {
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

	t.AppendRow(footer, rowConfigAutoMerge)
	t.SetAutoIndex(false)
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
		{Number: 2, AutoMerge: true},
		{Number: 3, AutoMerge: true},
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
