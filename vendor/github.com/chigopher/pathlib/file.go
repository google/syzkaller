package pathlib

import "github.com/spf13/afero"

// File represents a file in the filesystem. It inherits the afero.File interface
// but might also include additional functionality.
type File struct {
	afero.File
}
