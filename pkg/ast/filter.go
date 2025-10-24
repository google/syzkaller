
package ast

func (desc *Description) Filter(predicate func(Node) bool) *Description {
	desc1 := &Description{}
	for _, n := range desc.Nodes {
		if predicate(n) {
			desc1.Nodes = append(desc1.Nodes, n.Clone())
		}
	}
	return desc1
}
