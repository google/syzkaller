
package pages

import (
	_ "embed" // for go:embed directives
	"fmt"
	"html/template"
	"io/fs"
	"strings"

	"github.com/VerditeLabs/syzkaller/pkg/html"
)

func Create(page string) *template.Template {
	page = strings.Replace(page, "{{HEAD}}", getHeadTemplate(), 1)
	return template.Must(template.New("").Funcs(html.Funcs).Parse(page))
}

func CreateFromFS(fs fs.FS, patterns ...string) *template.Template {
	t := template.Must(template.New("syz-head").Funcs(html.Funcs).Parse(getHeadTemplate()))
	return template.Must(t.New("").Funcs(html.Funcs).ParseFS(fs, patterns...))
}

func getHeadTemplate() string {
	const headTempl = `<style type="text/css" media="screen">%v</style><script>%v</script>`
	return fmt.Sprintf(headTempl, style, js)
}

//go:embed style.css
var style string

//go:embed common.js
var js string
