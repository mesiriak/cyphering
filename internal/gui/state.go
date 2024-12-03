package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
	"github.com/mesiriak/cyphering/pkg/rsa"
	"strings"
)

type State struct {
	keys       *rsa.Keys
	serverKeys *rsa.Keys

	bitSize int

	application fyne.App
	window      fyne.Window

	publicKeyEntry       *widget.Entry
	privateKeyEntry      *widget.Entry
	serverPublicKeyEntry *widget.Entry
	nEntry               *widget.Entry
	serverNEntry         *widget.Entry

	requestEntry               *widget.Entry
	encodedRequestEntry        *widget.Entry
	serverEncodedResponseEntry *widget.Entry
	serverResponseEntry        *widget.Entry
}

func (s *State) clearKeysEntries() {
	s.publicKeyEntry.SetText("")
	s.privateKeyEntry.SetText("")
	s.serverPublicKeyEntry.SetText("")
	s.nEntry.SetText("")
	s.serverNEntry.SetText("")

	s.keys = nil
	s.serverKeys = nil
}

func (s *State) fillKeysEntries() {
	s.publicKeyEntry.SetText(s.keys.PublicKey.Text(10))
	s.privateKeyEntry.SetText(s.keys.PrivateKey.Text(10))
	s.nEntry.SetText(s.keys.N.Text(10))
}

func (s *State) fillServerKeysEntries() {
	s.serverPublicKeyEntry.SetText(s.serverKeys.PublicKey.Text(10))
	s.serverNEntry.SetText(s.serverKeys.N.Text(10))
}

func (s *State) checkSendingPossible() (bool, string) {
	if s.keys == nil || s.serverKeys == nil {
		return false, "You have to generate keys first."
	}

	if strings.TrimSpace(s.requestEntry.Text) == "" {
		return false, "Enter request data before sending."
	}

	return true, ""
}

var state = State{}
