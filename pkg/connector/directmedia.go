package connector

import (
	"context"
	"fmt"
	"io"

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

	log.Info().
		Uint64("cdn_id", info.CDNID).
		Str("cdn_key", info.CDNKey).
		Uint32("cdn_number", info.CDNNumber).
		Int("key_len", len(info.Key)).
		Int("digest_len", len(info.Digest)).
		Uint32("size", info.Size).
		Msg("Direct downloading media")

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
}
