// +build go1.10

package gce

import (
	"archive/tar"
)

func setGNUFormat(hdr *tar.Header) {
	hdr.Format = tar.FormatGNU
}
