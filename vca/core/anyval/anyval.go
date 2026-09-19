// SPDX-License-Identifier: Apache-2.0

// Package anyval reads values out of decoded JSON and CBOR documents.
// The helpers replace a discarded comma-ok or comma-error result with a
// named outcome, so that no error is dropped without a reason.
package anyval

import "io"

// As returns the value in v when v holds type T. It returns the zero value
// of T for a missing value or for any other type.
func As[T any](v any) T {
	t, isType := v.(T)
	if !isType {
		var zero T
		return zero
	}
	return t
}

// OrZero returns v when err is nil. It returns the zero value of T
// otherwise. Use it where a failure has no effect on the result.
func OrZero[T any](v T, err error) T {
	if err != nil {
		var zero T
		return zero
	}
	return v
}

// MustDo panics when err is not nil. Use it only for an operation that
// cannot fail, such as a close of a memory buffer.
func MustDo(err error) {
	if err != nil {
		panic(err)
	}
}

// Discard drops err on purpose. Use it where the failure has no effect on
// the result, such as the close of a body that was already read.
func Discard(err error) {
	_ = err
}

// Close closes c and drops the close error. Use it in a defer where the
// failure of a close has no effect on the result.
func Close(c io.Closer) {
	Discard(c.Close())
}

// Must returns v. It panics when err is not nil. Use it only for an
// operation that cannot fail, such as a write to a memory buffer.
func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
