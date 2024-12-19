package natTraversal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"testing"
)

var (
	stunSvr4 = "stun.ekiga.net:3478"
)

func TestGetPublicIP(t *testing.T) {
	fn := funcName(false)

	SetLogLevel(Trace)
	ipa, err := GetPublicIP(IPv4)
	if err != nil {
		t.Fatalf("%s: %v\n", fn, err)
	}
	fmt.Printf("Public IPv4 address: %s\n", ipa)

	ipa, err = GetPublicIP(IPv6)
	if err != nil {
		t.Fatalf("%s: %v\n", fn, err)
	}
	fmt.Printf("Public IPv6 address: %s\n", ipa)
}

func TestOpenEndpoint(t *testing.T) {
	fn := funcName(false)

	SetLogLevel(Trace)

	ep, err := NewEndpoint(100000) // must be fail
	if err == nil {
		t.Fatalf("%s: NewEndpoint(100000) Must fail.", fn)
	}
	if !errors.Is(err, ErrWrongPort) {
		t.Fatalf("%s: Error must be ErrWrongPort: %+v.", fn, err)
	}

	ep, err = NewEndpoint(54321)
	if err != nil {
		t.Fatalf("%s: %s\n", fn, err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	err = ep.OpenEndpoint(ctx, IPv4)
	if err == nil {
		fmt.Printf("\nep: %+v\n\n", ep)
	} else {
		t.Fatalf("%s: %s\n", fn, err)
	}
	ep.Reset()

	err = ep.OpenEndpoint(ctx, IPv6)
	if err == nil {
		fmt.Printf("\nep: %+v\n\n", ep)
	} else {
		t.Fatalf("%s: %s\n", fn, err)
	}

	ep.Close()
}

func TestGetReflexive(t *testing.T) {
	fn := funcName(false)

	SetLogLevel(Trace)

	ep, err := NewEndpoint(54321)
	if err != nil {
		t.Fatalf("%s: %s\n", fn, err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	err = ep.OpenEndpoint(ctx, IPv4)
	if err == nil {
		fmt.Printf("\nep: %+v\n\n", ep)
	} else {
		t.Fatalf("%s: %s\n", fn, err)
	}
}
