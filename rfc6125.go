/*
 * Copyright (c) 2020 Moriyoshi Koizumi
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *    * Neither the name of Elazar Leibovich. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package main

import (
	"strings"
)

func wildMatch(pattern string, target string) bool {
	state := 0
	ps := 0
	ts := 0
	var i int
	var c rune
	for i, c = range pattern {
		switch state {
		case 0:
			switch c {
			case '*':
				state = 1
			case '.':
				if ts >= len(target) {
					return false
				}
				var t string
				toe := strings.IndexByte(target[ts:], '.')
				if toe < 0 {
					t = target[ts:]
					ts = len(target)
				} else {
					t = target[ts : ts+toe]
					ts += toe + 1
				}
				if t != pattern[ps:i] {
					return false
				}
				ps = i + 1
			}
		case 1:
			switch c {
			case '.':
				state = 2
				ps = i + 1
			default:
				// invalid pattern; any characters after '*'
				return false
			}
		case 2:
			switch c {
			case '*':
				// reject "*.*"
				return false
			case '.':
				// consume until the component following "*" matches
				for {
					if ts >= len(target) {
						return false
					}
					toe := strings.IndexByte(target[ts:], '.')
					var t string
					if toe < 0 {
						t = target[ts:]
						ts = len(target)
					} else {
						t = target[ts : ts+toe]
						ts += toe + 1
					}
					if t == pattern[ps:i] {
						break
					}
				}
				state = 0
				ps = i + 1
			}
		}
	}
	i += 1
	switch state {
	case 0:
		if ts >= len(target) {
			return false
		}
		te := strings.IndexByte(target[ts:], '.')
		if te < 0 {
			te = len(target)
		} else {
			te += ts
		}
		if target[ts:te] != pattern[ps:i] {
			return false
		}
		ps = i
		ts = te + 1
	case 1:
		// trailing "*" can consume every component in the target
		ps += 1
		ts = len(target)
	case 2:
		for {
			if ts >= len(target) {
				return false
			}
			toe := strings.IndexByte(target[ts:], '.')
			var t string
			if toe < 0 {
				t = target[ts:]
				ts = len(target)
			} else {
				t = target[ts : ts+toe]
				ts += toe + 1
			}
			if t == pattern[ps:i] {
				break
			}
		}
		ps = i
	}
	return ps >= len(pattern) && ts >= len(target)
}
