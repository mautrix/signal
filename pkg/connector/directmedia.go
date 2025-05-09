package connector

import (
	"context"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/mediaproxy"

	"go.mau.fi/mautrix-signal/pkg/signalid"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
)

var _ bridgev2.DirectMediableNetwork = (*SignalConnector)(nil)

func (s *SignalConnector) SetUseDirectMedia() {
	s.useDirectMedia = true
}

func (s *SignalConnector) Download(ctx context.Context, mediaID networkid.MediaID, params map[string]string) (mediaproxy.GetMediaResponse, error) {
	log := zerolog.Ctx(ctx).With().Str("component", "direct download").Logger()

	info, err := signalid.ParseDirectMediaInfo(mediaID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse direct media id: %w", err)
	}

	switch info.Type {
	case signalid.DirectMediaAttachment:
		log.Info().
			Uint64("cdn_id", info.CDNID).
			Str("cdn_key", info.CDNKey).
			Uint32("cdn_number", info.CDNNumber).
			Int("key_len", len(info.Key)).
			Int("digest_len", len(info.Digest)).
			Uint32("size", info.Size).
			Msg("Direct downloading attachment")

		return &mediaproxy.GetMediaResponseCallback{
			Callback: func(w io.Writer) (int64, error) {
				data, err := signalmeow.DownloadAttachment(ctx, info.CDNID, info.CDNKey, info.CDNNumber, info.Key, info.Digest, info.Size)
				if err != nil {
					log.Err(err).Msg("Direct download failed")
					return 0, err
				}

				_, err = w.Write(data)
				return int64(info.Size), err
			},
		}, nil
	case signalid.DirectMediaGroupAvatar:
		log.Info().
			Hex("user_id", info.UserID).
			Hex("group_id", info.GroupID).
			Str("group_avatar_path", info.GroupAvatarPath).
			Msg("Direct downloading group avatar")

		userID, err := uuid.ParseBytes(info.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse user id: %w", err)
		}

		_, err = s.Bridge.GetExistingUserLoginByID(ctx, networkid.UserLoginID(userID.String()))
		if err != nil {
			return nil, fmt.Errorf("failed to get user login %w", err)
		}

		//client := userLogin.Client.(*SignalClient)
		//client.Client.DownloadGroupAvatar()

		return nil, fmt.Errorf("no downloader for direct media group avatar")
	case signalid.DirectMediaProfileAvatar:
		log.Info().
			Hex("user_id", info.UserID).
			Hex("contact_id", info.ContactID).
			Str("profile_avatar_path", info.ProfileAvatarPath).
			Msg("Direct downloading profile avatar")

		userID, err := uuid.ParseBytes(info.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse user id: %w", err)
		}

		_, err = s.Bridge.GetExistingUserLoginByID(ctx, networkid.UserLoginID(userID.String()))
		if err != nil {
			return nil, fmt.Errorf("failed to get user login %w", err)
		}

		//client := userLogin.Client.(*SignalClient)
		//client.Client.DownloadUserAvatar()

		return nil, fmt.Errorf("no downloader for direct media group avatar")
	default:
		return nil, fmt.Errorf("no downloader for direct media type: %d", info.Type)
	}
}
