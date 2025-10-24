
package covermerger

type DeletedFileLineMerger struct {
}

func (a *DeletedFileLineMerger) Add(*FileRecord) {
}

func (a *DeletedFileLineMerger) Result() *MergeResult {
	return &MergeResult{
		FileExists: false,
	}
}
