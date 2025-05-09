// mautrix-signal - A Matrix-Signal puppeting bridge.
// Copyright (C) 2025 Tulir Asokan
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

package signalid

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"maunium.net/go/mautrix/bridgev2/networkid"
)

// DirectMediaInfo is the information that is encoded in the media ID when
// using direct media.
//
// All integer fields are packed with variable length encoding, strings and
// byte slices are prefixed with varint length. Order is from top to bottom.
type DirectMediaInfo struct {
	CDNID     uint64
	CDNKey    string
	CDNNumber uint32
	Key       []byte
	Digest    []byte
	Size      uint32
}

func (m DirectMediaInfo) AsMediaID() (networkid.MediaID, error) {
	var mediaID networkid.MediaID
	buf := &bytes.Buffer{}

	// version byte
	if err := binary.Write(buf, binary.BigEndian, byte(0)); err != nil {
		return mediaID, err
	}

	// v0
	if err := writeUvarint(buf, m.CDNID); err != nil {
		return mediaID, err
	} else if err := writeByteSlice(buf, []byte(m.CDNKey)); err != nil {
		return mediaID, err
	} else if err := writeUvarint(buf, uint64(m.CDNNumber)); err != nil {
		return mediaID, err
	} else if err := writeByteSlice(buf, m.Key); err != nil {
		return mediaID, err
	} else if err := writeByteSlice(buf, m.Digest); err != nil {
		return mediaID, err
	} else if err := writeUvarint(buf, uint64(m.Size)); err != nil {
		return mediaID, err
	}

	return networkid.MediaID(buf.Bytes()), nil
}

func ParseDirectMediaInfo(mediaID networkid.MediaID) (info DirectMediaInfo, err error) {
	mediaIDLen := len(mediaID)
	if mediaIDLen == 0 {
		return info, fmt.Errorf("empty media ID")
	}

	buf := bufio.NewReader(bytes.NewBuffer(mediaID))

	// version byte
	var version byte
	if err := binary.Read(buf, binary.BigEndian, &version); err != nil {
		return info, err
	} else if version != 0 {
		return info, fmt.Errorf("invalid version %d", version)
	}

	// v0
	if info.CDNID, err = binary.ReadUvarint(buf); err != nil {
		return info, fmt.Errorf("failed to read cdn id: %w", err)
	}
	if cdnKey, err := readByteSlice(buf, mediaIDLen); err != nil {
		return info, fmt.Errorf("failed to read cdn key: %w", err)
	} else {
		info.CDNKey = string(cdnKey)
	}
	if cdnNumber, err := binary.ReadUvarint(buf); err != nil {
		return info, fmt.Errorf("failed to read cdn number: %w", err)
	} else {
		info.CDNNumber = uint32(cdnNumber)
	}
	if info.Key, err = readByteSlice(buf, mediaIDLen); err != nil {
		return info, fmt.Errorf("failed to read key: %w", err)
	} else if info.Digest, err = readByteSlice(buf, mediaIDLen); err != nil {
		return info, fmt.Errorf("failed to read digest: %w", err)
	}
	if size, err := binary.ReadUvarint(buf); err != nil {
		return info, fmt.Errorf("failed to read cdn id: %w", err)
	} else {
		info.Size = uint32(size)
	}

	return info, nil
}

func HashMediaID(mediaID networkid.MediaID) [32]byte {
	return sha256.Sum256(mediaID)
}

func writeUvarint(w io.Writer, i uint64) error {
	_, err := w.Write(binary.AppendUvarint(nil, i))
	return err
}

func writeByteSlice(w io.Writer, b []byte) error {
	if err := writeUvarint(w, uint64(len(b))); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readByteSlice(r *bufio.Reader, maxLength int) ([]byte, error) {
	length, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, fmt.Errorf("reading uvarint failed: %w", err)
	} else if int(length) > maxLength {
		return nil, fmt.Errorf("byte slice size larger than expected: %d > %d", length, maxLength)
	} else if length == 0 {
		return nil, nil
	}

	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	return buf, err
}
