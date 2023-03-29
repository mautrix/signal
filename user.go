package main

import (
	"errors"
	"go.mau.fi/mautrix-signal/database"
)

var (
	ErrNotConnected = errors.New("not connected")
	ErrNotLoggedIn  = errors.New("not logged in")
)

type User struct {
	*database.User
}

