package kstate

type KernStates []KernState

type KernState struct {
	ID    uint64
	Value uint64
}

func (state KernState) Hash() uint64 {
	return (state.ID & 0xffffffff) ^ state.Value
}

func (states KernStates) Merge(id uint64, value uint64) KernStates {
	for i, s := range states {
		/* duplicate state set */
		if (s.ID == id) && (s.Value == value) {
			return states
		}
		/* The state can't be stably trigger */
		if (s.Value != value) && (s.ID == id) {
			states = append(states[:i], states[i+1:]...)
			return states
		}
	}
	states = append(states, KernState{ID: id, Value: value})
	return states
}

func (states KernStates) Dedup() KernStates {
	dedupMap := make(map[uint32]bool)
	var retStates KernStates
	for _, s := range states {
		id := uint32(s.ID & 0xffffffff)
		val := uint32(s.Value & 0xffffffff)
		if _, ok := dedupMap[id ^ val]; !ok {
			dedupMap[id ^ val] = true
			retStates = append(retStates, s)
		}
	}
	return retStates;
}

func (states KernStates) Len() int {
	return len([]KernState(states))
}
