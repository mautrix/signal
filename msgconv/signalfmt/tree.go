// mautrix-signal - A Matrix-Signal puppeting bridge.
// Copyright (C) 2023 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package signalfmt

type BodyRange struct {
	Start  int
	Length int
	Value  BodyRangeValue
}

func (b BodyRange) End() int {
	return b.Start + b.Length
}

func (b BodyRange) Offset(offset int) *BodyRange {
	b.Start += offset
	return &b
}

func (b BodyRange) ChangeStart(startAt int) *BodyRange {
	b.Length -= startAt - b.Start
	b.Start = startAt
	return &b
}

func (b BodyRange) EndBefore(maxEnd int) *BodyRange {
	if b.End() > maxEnd {
		b.Length = maxEnd - b.Start
	}
	return &b
}

type LinkedRangeTree struct {
	Node    *BodyRange
	Sibling *LinkedRangeTree
	Child   *LinkedRangeTree
}

func ptrAdd(to **LinkedRangeTree, r *BodyRange) {
	if *to == nil {
		*to = &LinkedRangeTree{}
	}
	(*to).Add(r)
}

func (lrt *LinkedRangeTree) Add(r *BodyRange) {
	if lrt.Node == nil {
		lrt.Node = r
		return
	}
	lrtEnd := lrt.Node.End()
	if r.Start >= lrtEnd {
		ptrAdd(&lrt.Sibling, r.Offset(-lrtEnd))
		return
	}
	if r.End() > lrtEnd {
		ptrAdd(&lrt.Sibling, r.ChangeStart(lrtEnd).Offset(-lrtEnd))
	}
	ptrAdd(&lrt.Child, r.EndBefore(lrtEnd).Offset(-lrt.Node.Start))
}
