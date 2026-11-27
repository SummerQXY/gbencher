// Package eval evaluates rule expressions against collected data.
package eval

import (
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/SummerQXY/gbencher/internal/failure"
)

// Data is the shared result tree produced by collection steps.
type Data struct {
	mu       sync.RWMutex
	values   map[string]any
	failures []failureRecord
}

type failureRecord struct {
	elem   any
	failed Failed
}

// Failed describes a collection failure associated with a step and, when possible, an element.
type Failed struct {
	Step, Status, Reason string
	Failure              *failure.Failure
}

// NewData creates an empty, concurrency-safe result tree.
func NewData() *Data { return &Data{values: make(map[string]any)} }

// Set stores a collection result under its step identifier.
func (d *Data) Set(step string, v any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.values[step] = v
}

// Get returns the collection result for step.
func (d *Data) Get(step string) (any, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	v, ok := d.values[step]
	return v, ok
}

// Attach mutates the original data element so expressions can use the collected value.
func (d *Data) Attach(elem map[string]any, field string, v any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	elem[field] = v
}

// Fail records a collection failure, associating maps by object identity.
func (d *Data) Fail(elem any, step, status, reason string, f *failure.Failure) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failures = append(d.failures, failureRecord{elem: elem, failed: Failed{Step: step, Status: status, Reason: reason, Failure: f}})
}

// Failures returns failures associated with elem, sorted by step.
func (d *Data) Failures(elem any) []Failed {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []Failed
	for _, record := range d.failures {
		if sameMap(record.elem, elem) {
			out = append(out, record.failed)
		}
	}
	sortFailures(out)
	return out
}

// Unattributed returns failures without a known map element association.
func (d *Data) Unattributed(known []any) []Failed {
	knownMaps := make(map[uintptr]struct{}, len(known))
	for _, elem := range known {
		if ptr, ok := mapPointer(elem); ok {
			knownMaps[ptr] = struct{}{}
		}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []Failed
	for _, record := range d.failures {
		ptr, isMap := mapPointer(record.elem)
		if !isMap {
			out = append(out, record.failed)
			continue
		}
		if _, ok := knownMaps[ptr]; !ok {
			out = append(out, record.failed)
		}
	}
	sortFailures(out)
	return out
}

// OriginalObjects rejects constructed maps that are not present in d's data tree.
func OriginalObjects(d *Data, elems []any) error {
	d.mu.RLock()
	known := make(map[uintptr]struct{})
	for _, value := range d.values {
		collectMapPointers(value, known)
	}
	d.mu.RUnlock()
	for i, elem := range elems {
		ptr, ok := mapPointer(elem)
		if !ok {
			continue
		}
		if _, found := known[ptr]; !found {
			return fmt.Errorf("element %d is not an original data object", i)
		}
	}
	return nil
}

func collectMapPointers(value any, seen map[uintptr]struct{}) {
	if value == nil {
		return
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Map:
		ptr := rv.Pointer()
		if _, exists := seen[ptr]; exists {
			return
		}
		seen[ptr] = struct{}{}
		iter := rv.MapRange()
		for iter.Next() {
			collectMapPointers(iter.Value().Interface(), seen)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			collectMapPointers(rv.Index(i).Interface(), seen)
		}
	}
}

func mapPointer(value any) (uintptr, bool) {
	if value == nil {
		return 0, false
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Map || rv.IsNil() {
		return 0, false
	}
	return rv.Pointer(), true
}

func sameMap(a, b any) bool {
	pa, oka := mapPointer(a)
	pb, okb := mapPointer(b)
	return oka && okb && pa == pb
}

func sortFailures(failures []Failed) {
	sort.SliceStable(failures, func(i, j int) bool { return failures[i].Step < failures[j].Step })
}
