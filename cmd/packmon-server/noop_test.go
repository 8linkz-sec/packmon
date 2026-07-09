package main

import "github.com/8linkz-sec/packmon/internal/devstore"

type noopStore = devstore.Store
type noopPinger = devstore.Pinger

func newNoopStore() *noopStore {
	return devstore.NewStore()
}
