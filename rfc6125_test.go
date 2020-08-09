package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWild(t *testing.T) {
	cases := []struct {
		expected bool
		pattern  string
		target   string
	}{
		{
			expected: false,
			pattern:  "foo",
			target:   "bar",
		},
		{
			expected: true,
			pattern:  "foo",
			target:   "foo",
		},
		{
			expected: false,
			pattern:  "foo",
			target:   "foo.bar",
		},
		{
			expected: false,
			pattern:  "foo.bar",
			target:   "foo",
		},
		{
			expected: true,
			pattern:  "foo.bar",
			target:   "foo.bar",
		},
		{
			expected: true,
			pattern:  "*",
			target:   "foo",
		},
		{
			expected: true,
			pattern:  "*",
			target:   "foo.bar",
		},
		{
			expected: true,
			pattern:  "*.bar",
			target:   "foo.bar",
		},
		{
			expected: false,
			pattern:  "*.boo",
			target:   "foo",
		},
		{
			expected: false,
			pattern:  "*.boo",
			target:   "foo.bar",
		},
	}
	for _, case_ := range cases {
		t.Run(fmt.Sprintf("%s/%s", case_.pattern, case_.target), func(t *testing.T) {
			result := wildMatch(case_.pattern, case_.target)
			assert.Equal(t, case_.expected, result)
		})
	}
}
