package kstate

type KernStates []KernState

type KernState struct {
	ID    uint64
	Value uint64
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

func (states KernStates) Len() int {
	return len([]KernState(states))
}
