// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2024 Tulir Asokan
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

package signalmeow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"go.mau.fi/util/exerrors"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/proto"

	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

func (cli *Client) SyncStorage(ctx context.Context) {
	//log := zerolog.Ctx(ctx).With().Str("action", "sync storage").Logger()
	// TODO implement
}

type StorageUpdate struct {
	Version        uint64
	NewRecords     []*DecryptedStorageRecord
	RemovedRecords []string
	MissingRecords []string
}

func (cli *Client) FetchStorage(ctx context.Context, masterKey []byte, currentVersion uint64, existingKeys []string) (*StorageUpdate, error) {
	storageKey := deriveStorageServiceKey(masterKey)
	manifest, err := cli.fetchStorageManifest(ctx, storageKey, currentVersion)
	if err != nil {
		return nil, err
	} else if manifest == nil {
		return nil, nil
	}
	removedKeys := make([]string, 0)
	newKeys := manifestRecordToMap(manifest.GetIdentifiers())
	slices.Sort(existingKeys)
	existingKeys = slices.Compact(existingKeys)
	for _, key := range existingKeys {
		_, isStillThere := newKeys[key]
		if isStillThere {
			delete(newKeys, key)
		} else {
			removedKeys = append(removedKeys, key)
		}
		delete(newKeys, key)
	}
	newRecords, missingKeys, err := cli.fetchStorageRecords(ctx, storageKey, newKeys)
	if err != nil {
		return nil, err
	}
	return &StorageUpdate{
		Version:        manifest.GetVersion(),
		NewRecords:     newRecords,
		RemovedRecords: removedKeys,
		MissingRecords: missingKeys,
	}, nil
}

func manifestRecordToMap(manifest []*signalpb.ManifestRecord_Identifier) map[string]signalpb.ManifestRecord_Identifier_Type {
	manifestMap := make(map[string]signalpb.ManifestRecord_Identifier_Type, len(manifest))
	for _, item := range manifest {
		manifestMap[base64.StdEncoding.EncodeToString(item.GetRaw())] = item.GetType()
	}
	return manifestMap
}

func deriveStorageServiceKey(masterKey []byte) []byte {
	h := hmac.New(sha256.New, masterKey)
	h.Write([]byte("Storage Service Encryption"))
	return h.Sum(nil)
}

func deriveStorageManifestKey(storageKey []byte, version uint64) []byte {
	h := hmac.New(sha256.New, storageKey)
	exerrors.Must(fmt.Fprintf(h, "Manifest_%d", version))
	return h.Sum(nil)
}

func deriveStorageItemKey(storageKey []byte, itemID string) []byte {
	h := hmac.New(sha256.New, storageKey)
	exerrors.Must(fmt.Fprintf(h, "Item_%s", itemID))
	return h.Sum(nil)
}

// MaxReadStorageRecords is the maximum number of storage records to fetch at once
// from https://github.com/signalapp/Signal-Desktop/blob/v6.44.0/ts/services/storageConstants.ts
const MaxReadStorageRecords = 2500

type DecryptedStorageRecord struct {
	ItemType      signalpb.ManifestRecord_Identifier_Type
	StorageID     string
	StorageRecord *signalpb.StorageRecord
}

func (cli *Client) fetchStorageManifest(ctx context.Context, storageKey []byte, greaterThanVersion uint64) (*signalpb.ManifestRecord, error) {
	storageCreds, err := cli.getStorageCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credentials: %w", err)
	}
	path := "/v1/storage/manifest"
	if greaterThanVersion > 0 {
		path += fmt.Sprintf("/version/%d", greaterThanVersion)
	}
	var encryptedManifest signalpb.StorageManifest
	var manifestRecord signalpb.ManifestRecord
	resp, err := web.SendHTTPRequest(ctx, http.MethodGet, path, &web.HTTPReqOpt{
		Username:    &storageCreds.Username,
		Password:    &storageCreds.Password,
		ContentType: web.ContentTypeProtobuf,
		Host:        web.StorageHostname,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch storage manifest: %w", err)
	} else if resp.StatusCode == http.StatusNoContent {
		// Already up to date
		return nil, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d fetching storage manifest", resp.StatusCode)
	} else if body, err := io.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read storage manifest response: %w", err)
	} else if err = proto.Unmarshal(body, &encryptedManifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted storage manifest: %w", err)
	} else if decryptedManifestBytes, err := decryptBytes(deriveStorageManifestKey(storageKey, encryptedManifest.GetVersion()), encryptedManifest.GetValue()); err != nil {
		return nil, fmt.Errorf("failed to decrypt storage manifest: %w", err)
	} else if err = proto.Unmarshal(decryptedManifestBytes, &manifestRecord); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted manifest record: %w", err)
	} else {
		return &manifestRecord, nil
	}
}

func (cli *Client) fetchStorageRecords(ctx context.Context, storageKey []byte, inputRecords map[string]signalpb.ManifestRecord_Identifier_Type) ([]*DecryptedStorageRecord, []string, error) {
	recordKeys := make([][]byte, 0, len(inputRecords))
	for key := range inputRecords {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode storage key %s: %w", key, err)
		}
		recordKeys = append(recordKeys, decoded)
	}
	items := make([]*signalpb.StorageItem, 0, len(inputRecords))
	for i := 0; i < len(recordKeys); i += MaxReadStorageRecords {
		end := i + MaxReadStorageRecords
		if len(recordKeys) < end {
			end = len(recordKeys)
		}
		keyChunk := recordKeys[i:end]
		itemChunk, err := cli.fetchStorageItemsChunk(ctx, keyChunk)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, itemChunk...)
	}
	records := make([]*DecryptedStorageRecord, len(items))
	for i, encryptedItem := range items {
		base64Key := base64.StdEncoding.EncodeToString(encryptedItem.GetKey())
		itemKey := deriveStorageItemKey(storageKey, base64Key)
		decryptedItemBytes, err := decryptBytes(itemKey, encryptedItem.GetValue())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt storage item #%d (%s): %w", i+1, base64Key, err)
		}
		var decryptedItem signalpb.StorageRecord
		err = proto.Unmarshal(decryptedItemBytes, &decryptedItem)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal decrypted storage item #%d (%s): %w", i+1, base64Key, err)
		}
		itemType, ok := inputRecords[base64Key]
		if !ok {
			return nil, nil, fmt.Errorf("received unexpected storage item at index #%d: %s", i+1, base64Key)
		}
		delete(inputRecords, base64Key)
		records[i] = &DecryptedStorageRecord{
			ItemType:      itemType,
			StorageID:     base64Key,
			StorageRecord: &decryptedItem,
		}
	}
	missingKeys := maps.Keys(inputRecords)
	return records, missingKeys, nil
}

func (cli *Client) fetchStorageItemsChunk(ctx context.Context, recordKeys [][]byte) ([]*signalpb.StorageItem, error) {
	storageCreds, err := cli.getStorageCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credentials: %w", err)
	}
	body, err := proto.Marshal(&signalpb.ReadOperation{ReadKey: recordKeys})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal read operation: %w", err)
	}
	var storageItems signalpb.StorageItems
	resp, err := web.SendHTTPRequest(ctx, http.MethodPut, "/v1/storage/read", &web.HTTPReqOpt{
		Username:    &storageCreds.Username,
		Password:    &storageCreds.Password,
		Body:        body,
		ContentType: web.ContentTypeProtobuf,
		Host:        web.StorageHostname,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch storage records: %w", err)
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d fetching storage records", resp.StatusCode)
	} else if body, err := io.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read storage manifest response: %w", err)
	} else if err = proto.Unmarshal(body, &storageItems); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted storage manifest: %w", err)
	} else {
		return storageItems.GetItems(), nil
	}
}
