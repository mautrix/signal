package connector

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	bridgev2database "maunium.net/go/mautrix/bridgev2/database"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalid"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf/backuppb"
	signalstore "go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

func TestLifecycleContextReplacementCancelsPrevious(t *testing.T) {
	client := &SignalClient{}

	firstCtx := client.newLifecycleContext(context.Background())
	secondCtx := client.newLifecycleContext(context.Background())

	select {
	case <-firstCtx.Done():
	default:
		t.Fatal("expected previous lifecycle context to be canceled")
	}
	select {
	case <-secondCtx.Done():
		t.Fatal("expected current lifecycle context to remain active")
	default:
	}

	client.cancelLifecycleContext()

	select {
	case <-secondCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected lifecycle context to be canceled")
	}
}

func TestSyncChatsStopsOnContextCancellation(t *testing.T) {
	recipientLookupStarted := make(chan struct{})
	backupStore := &backupStoreStub{
		getBackupChatsFn: func(context.Context) ([]*signalstore.BackupChat, error) {
			return []*signalstore.BackupChat{{
				Chat: &backuppb.Chat{
					Id:          1,
					RecipientId: 2,
				},
			}}, nil
		},
		getBackupRecipientFn: func(ctx context.Context, recipientID uint64) (*backuppb.Recipient, error) {
			close(recipientLookupStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	client := &SignalClient{
		UserLogin: newTestUserLogin(),
		Client: &signalmeow.Client{
			Store: &signalstore.Device{
				BackupStore: backupStore,
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		client.syncChats(ctx)
		close(done)
	}()

	select {
	case <-recipientLookupStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for backup recipient lookup")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("syncChats did not exit after context cancellation")
	}
	if client.UserLogin.Metadata.(*signalid.UserLoginMetadata).ChatsSynced {
		t.Fatal("expected chat sync to stop before marking metadata as synced")
	}
}

func TestSyncChatSkipsMissingBackupRecipient(t *testing.T) {
	backupStore := &backupStoreStub{
		getBackupRecipientFn: func(context.Context, uint64) (*backuppb.Recipient, error) {
			return nil, nil
		},
	}

	client := &SignalClient{
		Client: &signalmeow.Client{
			Store: &signalstore.Device{
				BackupStore: backupStore,
			},
		},
	}

	ok := client.syncChat(context.Background(), &signalstore.BackupChat{
		Chat: &backuppb.Chat{
			Id:          1,
			RecipientId: 2,
		},
	})

	if !ok {
		t.Fatal("expected missing backup recipient to be skipped")
	}
}

func newTestUserLogin() *bridgev2.UserLogin {
	return &bridgev2.UserLogin{
		UserLogin: &bridgev2database.UserLogin{
			Metadata: &signalid.UserLoginMetadata{},
		},
		Log: zerolog.Nop(),
	}
}

type backupStoreStub struct {
	getBackupChatsFn     func(context.Context) ([]*signalstore.BackupChat, error)
	getBackupRecipientFn func(context.Context, uint64) (*backuppb.Recipient, error)
	deleteBackupChatFn   func(context.Context, uint64) error
}

func (b *backupStoreStub) AddBackupRecipient(context.Context, *backuppb.Recipient) error {
	return nil
}

func (b *backupStoreStub) AddBackupChat(context.Context, *backuppb.Chat) error {
	return nil
}

func (b *backupStoreStub) AddBackupChatItem(context.Context, *backuppb.ChatItem) error {
	return nil
}

func (b *backupStoreStub) RecalculateChatCounts(context.Context) error {
	return nil
}

func (b *backupStoreStub) ClearBackup(context.Context) error {
	return nil
}

func (b *backupStoreStub) GetBackupRecipient(ctx context.Context, recipientID uint64) (*backuppb.Recipient, error) {
	if b.getBackupRecipientFn != nil {
		return b.getBackupRecipientFn(ctx, recipientID)
	}
	return nil, nil
}

func (b *backupStoreStub) GetBackupChatByUserID(context.Context, libsignalgo.ServiceID) (*signalstore.BackupChat, error) {
	return nil, nil
}

func (b *backupStoreStub) GetBackupChatByGroupID(context.Context, types.GroupIdentifier) (*signalstore.BackupChat, error) {
	return nil, nil
}

func (b *backupStoreStub) GetBackupChats(ctx context.Context) ([]*signalstore.BackupChat, error) {
	if b.getBackupChatsFn != nil {
		return b.getBackupChatsFn(ctx)
	}
	return nil, nil
}

func (b *backupStoreStub) GetBackupChatItems(context.Context, uint64, time.Time, bool, int) ([]*backuppb.ChatItem, error) {
	return nil, nil
}

func (b *backupStoreStub) DeleteBackupChat(ctx context.Context, chatID uint64) error {
	if b.deleteBackupChatFn != nil {
		return b.deleteBackupChatFn(ctx, chatID)
	}
	return nil
}

func (b *backupStoreStub) DeleteBackupChatItems(context.Context, uint64, time.Time) error {
	return nil
}
