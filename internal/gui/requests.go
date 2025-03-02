package gui

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"fyne.io/fyne/v2/dialog"
	"github.com/mesiriak/cyphering/pkg/aes"
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
}

func sendJsonData() {
	isSendingPossible, alert := state.checkSendingPossible()

	if !isSendingPossible {
		dialog.NewInformation("Error during sending message", alert, state.window).Show()

		return
	}

	isJsonValid, alert := state.checkJsonValid()

	if !isJsonValid {
		dialog.NewInformation("Error during sending message", alert, state.window).Show()

		return
	}

	var unmarshalledJsonData interface{}

	if err := json.Unmarshal([]byte(state.requestEntry.Text), &unmarshalledJsonData); err != nil {
		dialog.NewInformation("Error during marshalling json", fmt.Sprintf("%s", err), state.window).Show()
	}

	encoded, err := rsa.EncryptStruct(
		unmarshalledJsonData,
		state.serverKeys.PublicKey,
		state.serverKeys.N,
	)

	if err != nil {
		dialog.NewInformation("Error during sending message", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	marshalledEncodedJson, err := json.Marshal(encoded)

	if err != nil {
		dialog.NewInformation("Error during marshalling json", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	state.encodedRequestEntry.SetText(string(marshalledEncodedJson))
}

func sendAESRawData() {
	isSendingPossible, alert := state.checkAESSendingPossible()

	if !isSendingPossible {
		dialog.NewInformation("Error during sending message", alert, state.window).Show()

		return
	}

	decodedKey, err := hex.DecodeString(state.aesKey)

	if err != nil {
		dialog.NewInformation("Error during decoding AES key", "Key cannot be decoded.", state.window).Show()

		return
	}

	encoded, err := aes.Encrypt(
		state.aesRequestEntry.Text,
		decodedKey,
		state.aesBitSize,
	)

	if err != nil {
		dialog.NewInformation("Error during sending AES message", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	state.aesEncodedRequestEntry.SetText(hex.EncodeToString([]byte(encoded)))
}
