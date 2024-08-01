package cui

import (
	"fmt"
	"os"
	"time"

	"github.com/jroimartin/gocui"
)

const (
	View = "prism"
)

type GoCui struct {
	g     *gocui.Gui
	start time.Time
}

func NewGoCui() (*GoCui, error) {
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		return nil, err
	}

	c := &GoCui{
		g:     g,
		start: time.Now(),
	}

	g.SetManagerFunc(func(g *gocui.Gui) error {
		return c.render()
	})

	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		g.Close()
		return nil, err
	}
	if err := g.SetKeybinding("", gocui.KeyEsc, gocui.ModNone, quit); err != nil {
		g.Close()
		return nil, err
	}
	if err := g.SetKeybinding("", 'q', gocui.ModNone, quit); err != nil {
		g.Close()
		return nil, err
	}

	go func() {
		g.MainLoop()
		g.Close()
		os.Exit(0)
	}()

	return c, nil
}

func (c *GoCui) WindowSize() (x, y int) {
	return c.g.Size()
}

func (c *GoCui) Render(content string) {
	c.g.Update(func(g *gocui.Gui) error {
		if view, err := c.g.View(View); err == nil {
			view.Clear()
			fmt.Fprintln(view, time.Now().Format(time.RFC3339), time.Since(c.start).Truncate(time.Second).String())
			fmt.Fprint(view, content)
			return nil
		} else {
			return err
		}
	})
}

func (c *GoCui) Exit() {
	c.g.Close()
}

func (c *GoCui) render() error {
	maxX, maxY := c.g.Size()
	if v, err := c.g.SetView(View, 0, 0, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Frame = false
		v.Wrap = false
	}

	return nil
}

func quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}
