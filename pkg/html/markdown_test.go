// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package html

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderMarkdown(t *testing.T) {
	got := RenderMarkdown(strings.ReplaceAll(`### Title

See ['fs/ext4/mmp.c'](https://example.com/mmp.c):
'''c
a < b
'''
`, "'", "`"))
	assert.Equal(t, `<h3>Title</h3>
<p>See <a href="https://example.com/mmp.c"><code>fs/ext4/mmp.c</code></a>:</p>
<pre><code class="language-c">a &lt; b
</code></pre>
`, string(got))

	// Raw HTML and dangerous links are not passed through.
	got = RenderMarkdown(`Text <script>alert(1)</script>

[x](javascript:alert(1))`)
	assert.Equal(t, `<p>Text <!-- raw HTML omitted -->alert(1)<!-- raw HTML omitted --></p>
<p><a href="">x</a></p>
`, string(got))
}
