// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package testutil

import (
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"testing"
	"testing/quick"
	"time"
)

func IterCount() int {
	iters := 1000
	if testing.Short() {
		iters /= 10
	}
	if RaceEnabled {
		iters /= 10
	}
	return iters
}

func RandSource(t *testing.T) rand.Source {
	seed := time.Now().UnixNano()
	if fixed := os.Getenv("SYZ_SEED"); fixed != "" {
		seed, _ = strconv.ParseInt(fixed, 0, 64)
	}
	if os.Getenv("CI") != "" {
		seed = 0 // required for deterministic coverage reports
	}
	t.Logf("seed=%v", seed)
	return rand.NewSource(seed)
}

func RandMountImage(r *rand.Rand) []byte {
	const maxLen = 1 << 20 // 1 MB.
	len := r.Intn(maxLen)
	slice := make([]byte, len)
	r.Read(slice)
	return slice
}

// RandValue creates a random value of the same type as the argument typ.
// It recursively fills structs/slices/maps similar to testing/quick.Value,
// but it handles time.Time as well w/o panicing (unfortunately testing/quick panics on time.Time).
func RandValue(t *testing.T, typ any) any {
	return randValue(t, rand.New(RandSource(t)), reflect.TypeOf(typ)).Interface()
}

func randValue(t *testing.T, rnd *rand.Rand, typ reflect.Type) reflect.Value {
	v := reflect.New(typ).Elem()
	switch typ.Kind() {
	default:
		ok := false
		v, ok = quick.Value(typ, rnd)
		if !ok {
			t.Fatalf("failed to generate random value of type %v", typ)
		}
	case reflect.Slice:
		size := rand.Intn(4)
		v.Set(reflect.MakeSlice(typ, size, size))
		fallthrough
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			v.Index(i).Set(randValue(t, rnd, typ.Elem()))
		}
	case reflect.Struct:
		if typ.String() == "time.Time" {
			v = reflect.ValueOf(time.UnixMilli(rnd.Int63()))
		} else {
			for i := 0; i < v.NumField(); i++ {
				v.Field(i).Set(randValue(t, rnd, typ.Field(i).Type))
			}
		}
	case reflect.Pointer:
		v.SetZero()
		if rand.Intn(2) == 0 {
			v.Set(reflect.New(typ.Elem()))
			v.Elem().Set(randValue(t, rnd, typ.Elem()))
		}
	case reflect.Map:
		v.Set(reflect.MakeMap(typ))
		for i := rand.Intn(4); i > 0; i-- {
			v.SetMapIndex(randValue(t, rnd, typ.Key()), randValue(t, rnd, typ.Elem()))
		}
	}
	return v
}

type Writer struct {
	testing.TB
}

func (w *Writer) Write(data []byte) (int, error) {
	w.TB.Logf("%s", data)
	return len(data), nil
}
