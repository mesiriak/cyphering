package gui

import (
	"fmt"
	"fyne.io/fyne/v2/dialog"
	"github.com/mesiriak/cyphering/pkg/rsa"
)

func sendRawData() {
	isSendingPossible, alert := state.checkSendingPossible()

	if !isSendingPossible {
		dialog.NewInformation("Error during sending message", alert, state.window).Show()

		return
	}

	encoded, err := rsa.Encrypt(
		state.requestEntry.Text,
		state.serverKeys.PublicKey,
		state.serverKeys.N,
	)

	if err != nil {
		dialog.NewInformation("Error during sending message", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	state.encodedRequestEntry.SetText(encoded)

	serverEncoded, err := rsa.Encrypt(
		state.requestEntry.Text,
		state.keys.PublicKey,
		state.keys.N,
	)

	if err != nil {
		dialog.NewInformation("Error during handling message", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	state.serverEncodedResponseEntry.SetText(serverEncoded)

	serverDecoded, err := rsa.Decrypt(
		encoded,
		state.serverKeys.PrivateKey,
		state.serverKeys.N,
	)

	if err != nil {
		dialog.NewInformation("Error during handling message", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	state.serverResponseEntry.SetText(serverDecoded)
}
