// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"fmt"
)

type Service struct {
	*Extractor
	perName   map[string]*Subsystem
	perParent map[*Subsystem][]*Subsystem
}

func MustMakeService(list []*Subsystem) *Service {
	if len(list) == 0 {
		panic("the subsystem list is empty")
	}
	service, err := MakeService(list)
	if err != nil {
		panic(fmt.Sprintf("service creation failed: %s", err))
	}
	return service
}

func MakeService(list []*Subsystem) (*Service, error) {
	extractor := MakeExtractor(list)
	perName := map[string]*Subsystem{}
	perParent := map[*Subsystem][]*Subsystem{}
	for _, item := range list {
		if item.Name == "" {
			return nil, fmt.Errorf("input contains a subsystem without a name")
		}
		if perName[item.Name] != nil {
			return nil, fmt.Errorf("collision on %#v name", item.Name)
		}
		perName[item.Name] = item
		for _, p := range item.Parents {
			perParent[p] = append(perParent[p], item)
		}
	}
	return &Service{
		Extractor: extractor,
		perName:   perName,
		perParent: perParent,
	}, nil
}

func (s *Service) ByName(name string) *Subsystem {
	return s.perName[name]
}

func (s *Service) List() []*Subsystem {
	ret := []*Subsystem{}
	for _, item := range s.perName {
		ret = append(ret, item)
	}
	return ret
}

func (s *Service) Children(parent *Subsystem) []*Subsystem {
	return append([]*Subsystem{}, s.perParent[parent]...)
}
