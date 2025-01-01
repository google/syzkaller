// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package genai

import (
	"context"
	"errors"
	"fmt"
	"time"

	gl "cloud.google.com/go/ai/generativelanguage/apiv1beta"
	pb "cloud.google.com/go/ai/generativelanguage/apiv1beta/generativelanguagepb"
	"google.golang.org/api/iterator"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	fieldmaskpb "google.golang.org/protobuf/types/known/fieldmaskpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

type cacheClient = gl.CacheClient

var (
	newCacheClient     = gl.NewCacheClient
	newCacheRESTClient = gl.NewCacheRESTClient
)

// GenerativeModelFromCachedContent returns a [GenerativeModel] that uses the given [CachedContent].
// The argument should come from a call to [Client.CreateCachedContent] or [Client.GetCachedContent].
func (c *Client) GenerativeModelFromCachedContent(cc *CachedContent) *GenerativeModel {
	return &GenerativeModel{
		c:                 c,
		fullName:          cc.Model,
		CachedContentName: cc.Name,
	}
}

// CreateCachedContent creates a new CachedContent.
// The argument should contain a model name and some data to be cached, which can include
// contents, a system instruction, tools and/or tool configuration. It can also
// include an expiration time or TTL. But it should not include a name; the system
// will generate one.
//
// The return value will contain the name, which should be used to refer to the CachedContent
// in other API calls. It will also hold various metadata like expiration and creation time.
// It will not contain any of the actual content provided as input.
//
// You can use the return value to create a model with [Client.GenerativeModelFromCachedContent].
// Or you can set [GenerativeModel.CachedContentName] to the name of the CachedContent, in which
// case you must ensure that the model provided in this call matches the name in the [GenerativeModel].
func (c *Client) CreateCachedContent(ctx context.Context, cc *CachedContent) (*CachedContent, error) {
	if cc.Name != "" {
		return nil, errors.New("genai.CreateCachedContent: do not provide a name; one will be generated")
	}
	pcc := cc.toProto()
	pcc.Model = Ptr(fullModelName(cc.Model))
	req := &pb.CreateCachedContentRequest{
		CachedContent: pcc,
	}
	debugPrint(req)
	return c.cachedContentFromProto(c.cc.CreateCachedContent(ctx, req))
}

// GetCachedContent retrieves the CachedContent with the given name.
func (c *Client) GetCachedContent(ctx context.Context, name string) (*CachedContent, error) {
	return c.cachedContentFromProto(c.cc.GetCachedContent(ctx, &pb.GetCachedContentRequest{Name: name}))
}

// DeleteCachedContent deletes the CachedContent with the given name.
func (c *Client) DeleteCachedContent(ctx context.Context, name string) error {
	return c.cc.DeleteCachedContent(ctx, &pb.DeleteCachedContentRequest{Name: name})
}

// CachedContentToUpdate specifies which fields of a CachedContent to modify in a call to
// [Client.UpdateCachedContent].
type CachedContentToUpdate struct {
	// If non-nil, update the expire time or TTL.
	Expiration *ExpireTimeOrTTL
}

// UpdateCachedContent modifies the [CachedContent] according to the values
// of the [CachedContentToUpdate] struct.
// It returns the modified CachedContent.
//
// The argument CachedContent must have its Name field populated.
// If its UpdateTime field is non-zero, it will be compared with the update time
// of the stored CachedContent and the call will fail if they differ.
// This avoids a race condition when two updates are attempted concurrently.
// All other fields of the argument CachedContent are ignored.
func (c *Client) UpdateCachedContent(ctx context.Context, cc *CachedContent, ccu *CachedContentToUpdate) (*CachedContent, error) {
	if ccu == nil || ccu.Expiration == nil {
		return nil, errors.New("genai.UpdateCachedContent: no update specified")
	}
	cc2 := &CachedContent{
		Name:       cc.Name,
		UpdateTime: cc.UpdateTime,
		Expiration: *ccu.Expiration,
	}
	mask := "expire_time"
	if ccu.Expiration.ExpireTime.IsZero() {
		mask = "ttl"
	}
	req := &pb.UpdateCachedContentRequest{
		CachedContent: cc2.toProto(),
		UpdateMask:    &fieldmaskpb.FieldMask{Paths: []string{mask}},
	}
	debugPrint(req)
	return c.cachedContentFromProto(c.cc.UpdateCachedContent(ctx, req))
}

// ListCachedContents lists all the CachedContents associated with the project and location.
func (c *Client) ListCachedContents(ctx context.Context) *CachedContentIterator {
	return &CachedContentIterator{
		it: c.cc.ListCachedContents(ctx, &pb.ListCachedContentsRequest{}),
	}
}

// A CachedContentIterator iterates over CachedContents.
type CachedContentIterator struct {
	it *gl.CachedContentIterator
}

// Next returns the next result. Its second return value is iterator.Done if there are no more
// results. Once Next returns Done, all subsequent calls will return Done.
func (it *CachedContentIterator) Next() (*CachedContent, error) {
	m, err := it.it.Next()
	if err != nil {
		return nil, err
	}
	return (CachedContent{}).fromProto(m), nil
}

// PageInfo supports pagination. See the google.golang.org/api/iterator package for details.
func (it *CachedContentIterator) PageInfo() *iterator.PageInfo {
	return it.it.PageInfo()
}

func (c *Client) cachedContentFromProto(pcc *pb.CachedContent, err error) (*CachedContent, error) {
	if err != nil {
		return nil, err
	}
	cc := (CachedContent{}).fromProto(pcc)
	return cc, nil
}

// ExpireTimeOrTTL describes the time when a resource expires.
// If ExpireTime is non-zero, it is the expiration time.
// Otherwise, the expiration time is the value of TTL ("time to live") added
// to the current time.
type ExpireTimeOrTTL struct {
	ExpireTime time.Time
	TTL        time.Duration
}

// populateCachedContentTo populates some fields of p from v.
func populateCachedContentTo(p *pb.CachedContent, v *CachedContent) {
	exp := v.Expiration
	if !exp.ExpireTime.IsZero() {
		p.Expiration = &pb.CachedContent_ExpireTime{
			ExpireTime: timestamppb.New(exp.ExpireTime),
		}
	} else if exp.TTL != 0 {
		p.Expiration = &pb.CachedContent_Ttl{
			Ttl: durationpb.New(exp.TTL),
		}
	}
	// If both fields of v.Expiration are zero, leave p.Expiration unset.
}

// populateCachedContentFrom populates some fields of v from p.
func populateCachedContentFrom(v *CachedContent, p *pb.CachedContent) {
	if p.Expiration == nil {
		return
	}
	switch e := p.Expiration.(type) {
	case *pb.CachedContent_ExpireTime:
		v.Expiration.ExpireTime = pvTimeFromProto(e.ExpireTime)
	case *pb.CachedContent_Ttl:
		v.Expiration.TTL = e.Ttl.AsDuration()
	default:
		panic(fmt.Sprintf("unknown type of CachedContent.Expiration: %T", p.Expiration))
	}
}
