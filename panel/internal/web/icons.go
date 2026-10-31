package web

import (
	"embed"
	"html/template"
	"regexp"
	"strings"
	"time"
)

// Icons are Tabler's outline icons (MIT, see static/vendor/LICENSES.txt), put inline into the page so that
// they need neither a font nor an extra request.
//
//go:embed icons/*.svg
var iconFiles embed.FS

var (
	iconAttrs = regexp.MustCompile(`\s+(width|height|class)="[^"]*"`)
	iconSpace = regexp.MustCompile(`>\s+<`)
	icons     = map[string]template.HTML{}
)

func init() {
	ents, _ := iconFiles.ReadDir("icons")
	for _, e := range ents {
		b, _ := iconFiles.ReadFile("icons/" + e.Name())
		svg := iconAttrs.ReplaceAllString(string(b), "")
		svg = iconSpace.ReplaceAllString(strings.TrimSpace(svg), "><")
		svg = strings.Replace(svg, "<svg", `<svg class="icon" aria-hidden="true" focusable="false"`, 1)
		icons[strings.TrimSuffix(e.Name(), ".svg")] = template.HTML(strings.Join(strings.Fields(svg), " "))
	}
}

// icon returns the inline SVG of a bundled icon; an unknown name is a mistake in a template, so it panics
// when the templates are first rendered in a test rather than showing an empty box.
func icon(name string) template.HTML {
	h, ok := icons[name]
	if !ok {
		panic("unknown icon " + name)
	}
	return h
}

// The people running the panel are in Singapore (UTC+8, no daylight saving), so times are shown there.
var shownZone = time.FixedZone("SGT", 8*3600)

const zoneLabel = "新加坡时间"

func showTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.In(shownZone).Format("2006-01-02 15:04:05")
}

func showClock(t time.Time) string { return t.In(shownZone).Format("01-02 15:04") }
