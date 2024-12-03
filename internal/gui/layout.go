package gui

import (
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/mesiriak/cyphering/pkg/rsa"
)

func NewGUI() (fyne.App, error) {
	state.application = app.New()
	state.window = state.application.NewWindow("Cyphering")

	// Set position and size.
	state.window.Resize(fyne.NewSize(1020, 640))
	state.window.CenterOnScreen()

	keysContainer := NewKeysContainer()
	keysManipulatorContainer := NewKeysManipulatorContainer()
	requestEntriesContainer := NewRequestEntriesContainer()
	requestButtonsContainer := NewRequestButtonsContainer()

	state.window.SetContent(
		container.NewVBox(
			keysContainer, keysManipulatorContainer, requestEntriesContainer, requestButtonsContainer,
		),
	)

	state.window.Show()

	return state.application, nil
}

func NewKeysContainer() *fyne.Container {
	publicKeyEntry, publicKeyLayout := NewKeyEntry("Client Public Key")
	privateKeyEntry, privateKeyLayout := NewKeyEntry("Client Private Key")
	serverPublicKeyEntry, serverPublicKeyLayout := NewKeyEntry("Server Public Key")

	nEntry, nEntryLayout := NewKeyEntry("Client N")
	serverNEntry, serverNLayout := NewKeyEntry("Server N")

	state.publicKeyEntry = publicKeyEntry
	state.privateKeyEntry = privateKeyEntry
	state.serverPublicKeyEntry = serverPublicKeyEntry
	state.nEntry = nEntry
	state.serverNEntry = serverNEntry

	return container.NewGridWithRows(
		2,
		container.NewGridWithColumns(3, publicKeyLayout, privateKeyLayout, serverPublicKeyLayout),
		container.NewGridWithColumns(2, nEntryLayout, serverNLayout),
	)
}

func NewKeysManipulatorContainer() *fyne.Container {
	keyBitSizeEntry := NewKeyBitSizeSelect(
		[]string{"32", "64", "128", "256", "512", "1024", "2048", "4096"},
	)

	generateKeysButton := widget.NewButton("Generate Keys", func() {
		if state.bitSize == 0 {
			dialog.NewInformation(
				"Error during generating keys",
				"Select correct bit size.",
				state.window,
			).Show()

			return
		}

		keys, err := rsa.GenerateKeys(state.bitSize)

		if err != nil {
			dialog.NewInformation(
				"Error happened",
				fmt.Sprintf("Error while generating rsa keys: %s", err),
				state.window,
			).Show()

			return
		}

		state.keys = keys
		state.fillKeysEntries()
	})

	exchangeKeysButton := widget.NewButton("Exchange Keys", func() {
		keys, err := rsa.GenerateKeys(state.bitSize)

		if state.keys == nil {
			dialog.NewInformation(
				"Error during exchanging",
				"Generate client keys first.",
				state.window,
			).Show()

			return
		}

		if err != nil {
			dialog.NewInformation(
				"Error happened",
				fmt.Sprintf("Error while generating rsa keys: %s", err),
				state.window,
			).Show()

			return
		}

		state.serverKeys = keys
		state.fillServerKeysEntries()
	})

	return container.NewGridWithRows(1, keyBitSizeEntry, generateKeysButton, exchangeKeysButton)
}

func NewRequestEntriesContainer() *fyne.Container {
	requestEntry, requestEntryLayout := NewRequestEntry(true)
	encodedRequestEntry, encodedRequestEntryLayout := NewRequestEntry(false)
	encodedResponseEntry, encodedResponseEntryLayout := NewRequestEntry(false)
	responseEntry, responseEntryLayout := NewRequestEntry(false)

	state.requestEntry = requestEntry
	state.encodedRequestEntry = encodedRequestEntry
	state.serverResponseEntry = responseEntry
	state.serverEncodedResponseEntry = encodedResponseEntry

	return container.NewVBox(
		container.NewGridWithColumns(
			4,
			NewHeaderLabel("Request"),
			NewHeaderLabel("Encoded Request"),
			NewHeaderLabel("Encoded Response"),
			NewHeaderLabel("Response"),
		),
		container.NewGridWrap(
			fyne.Size{Height: 400, Width: 250},
			requestEntryLayout,
			encodedRequestEntryLayout,
			encodedResponseEntryLayout,
			responseEntryLayout,
		),
	)
}

func NewRequestButtonsContainer() *fyne.Container {

	sendRawButton := widget.NewButton("Send raw", sendRawData)

	sendJsonButton := widget.NewButton("Send JSON", func() {

	})

	return container.NewGridWithColumns(2, sendRawButton, sendJsonButton)
}
