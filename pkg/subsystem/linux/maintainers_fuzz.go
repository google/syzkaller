
package linux

import "bytes"

func Fuzz(data []byte) int {
	parseLinuxMaintainers(bytes.NewReader(data))
	return 0
}
