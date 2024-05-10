package pathlib

import "os"

// DefaultFileMode is the file mode that will be applied to new pathlib files
var DefaultFileMode = os.FileMode(0o644)

// DefaultDirMode is the default mode that will be applied to new directories
var DefaultDirMode = os.FileMode(0o755)
