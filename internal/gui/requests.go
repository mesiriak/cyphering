package gui

import (
	"encoding/json"
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

	var unmarshalledServerEncodedJsonData interface{}

	if err := json.Unmarshal([]byte(state.requestEntry.Text), &unmarshalledServerEncodedJsonData); err != nil {
		dialog.NewInformation("Error during marshalling json", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	serverEncoded, err := rsa.EncryptStruct(
		unmarshalledServerEncodedJsonData,
		state.keys.PublicKey,
		state.keys.N,
	)

	if err != nil {
		dialog.NewInformation("Error during handling message", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	marshalledServerEncodedJson, err := json.Marshal(serverEncoded)

	if err != nil {
		dialog.NewInformation("Error during marshalling json", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	state.serverEncodedResponseEntry.SetText(string(marshalledServerEncodedJson))

	serverDecoded, err := rsa.DecryptStruct(
		encoded,
		state.serverKeys.PrivateKey,
		state.serverKeys.N,
	)

	if err != nil {
		dialog.NewInformation("Error during handling message", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	marshalledServerDecodedJson, err := json.Marshal(serverDecoded)

	if err != nil {
		dialog.NewInformation("Error during marshalling json", fmt.Sprintf("%s", err), state.window).Show()

		return
	}

	state.serverResponseEntry.SetText(string(marshalledServerDecodedJson))
}
