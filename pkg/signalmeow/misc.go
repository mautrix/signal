package signalmeow

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

func serverPublicParams() libsignalgo.ServerPublicParams {
	serverPublicParamsBase64 := "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P"
	serverPublicParamsBytes, err := base64.StdEncoding.DecodeString(serverPublicParamsBase64)
	if err != nil {
		panic(err)
	}
	var serverPublicParams libsignalgo.ServerPublicParams
	copy(serverPublicParams[:], serverPublicParamsBytes)
	return serverPublicParams
}

func convertUUIDToByteUUID(uuid string) (*libsignalgo.UUID, error) {
	uuid = strings.Replace(uuid, "-", "", -1)
	uuidBytes, err := hex.DecodeString(uuid)
	if err != nil {
		return nil, err
	}
	if len(uuidBytes) != 16 {
		return nil, errors.New("invalid UUID length")
	}
	byteUUID := libsignalgo.UUID(uuidBytes)
	return &byteUUID, nil
}
