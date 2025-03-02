package gui

import (
	"encoding/hex"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/mesiriak/cyphering/pkg/aes"
	"github.com/mesiriak/cyphering/pkg/rsa"
)

func NewGUI() (fyne.App, error) {
	state.application = app.New()
	state.window = state.application.NewWindow("Cyphering")

	// Set position and size.
	state.window.Resize(fyne.NewSize(1020, 960))
	state.window.CenterOnScreen()
	state.window.SetFixedSize(true)

	keysContainer := NewRSAKeysContainer()
	keysManipulatorContainer := NewRSAKeysManipulatorContainer()
	requestEntriesContainer := NewRequestEntriesContainer()
	requestButtonsContainer := NewRequestButtonsContainer()

	aesKeysManipulatorContainer := NewAESKeysManipulatorContainer()
	aesRequestEntriesContainer := NewAESRequestEntriesContainer()
	aesRequestButtonsContainer := NewAESRequestButtonsContainer()

	state.window.SetContent(
		container.NewVBox(
			keysContainer,
			keysManipulatorContainer,
			requestEntriesContainer,
			requestButtonsContainer,
			aesKeysManipulatorContainer,
			aesRequestEntriesContainer,
			aesRequestButtonsContainer,
		),
	)

	state.window.Show()

	return state.application, nil
}

func NewRSAKeysContainer() *fyne.Container {
	publicKeyEntry, publicKeyLayout := NewKeyEntry("Client Public Key", false)
	privateKeyEntry, privateKeyLayout := NewKeyEntry("Client Private Key", false)
	serverPublicKeyEntry, serverPublicKeyLayout := NewKeyEntry("Server Public Key", false)

	nEntry, nEntryLayout := NewKeyEntry("Client N", false)
	serverNEntry, serverNLayout := NewKeyEntry("Server N", false)

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

func NewRSAKeysManipulatorContainer() *fyne.Container {
	keyBitSizeEntry := NewRSAKeyBitSizeSelect(
		[]string{"32", "64", "128", "256", "512", "1024", "2048", "4096"},
	)

	generateKeysButton := widget.NewButton("Generate Keys", func() {
		if state.bitSize == 0 {
			dialog.NewInformation(
				"Error during generating keys",
				"Select correct RSA bit size.",
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

func NewAESKeysManipulatorContainer() *fyne.Container {
	aesKeyBitSizeEntry := NewAESKeyBitSizeSelect(
		[]string{"128", "192", "256"},
	)

	aesKeyEntry, aesKeyEntryLayout := NewKeyEntry("AES Keys", true)

	state.aesKeyEntry = aesKeyEntry

	generateKeysButton := widget.NewButton("Generate AES Keys", func() {
		if state.aesBitSize == 0 {
			dialog.NewInformation(
				"Error during generating keys",
				"Select correct AES bit size.",
				state.window,
			).Show()

			return
		}

		key, err := aes.GenerateRandomKey(state.aesBitSize)

		if err != nil {
			dialog.NewInformation(
				"Error happened",
				fmt.Sprintf("Error while generating AES keys: %s", err),
				state.window,
			).Show()
		}

		state.aesKey = hex.EncodeToString(key)
		state.fillAESKeysEntries()
	})

	return container.NewGridWithRows(
		2,
		NewHeaderLabel("AES Key"),
		container.NewGridWithRows(1, aesKeyBitSizeEntry, aesKeyEntryLayout, generateKeysButton),
	)
}

func NewRequestEntriesContainer() *fyne.Container {
	requestEntry, requestEntryLayout := NewRequestEntry(true)
	encodedRequestEntry, encodedRequestEntryLayout := NewRequestEntry(false)

	state.requestEntry = requestEntry
	state.encodedRequestEntry = encodedRequestEntry

	return container.NewVBox(
		container.NewGridWrap(
			fyne.Size{Height: 40, Width: 1020},
			NewHeaderLabel("RSA Text"),
		),
		container.NewGridWrap(
			fyne.Size{Height: 100, Width: 1020},
			requestEntryLayout,
		),
		container.NewGridWrap(
			fyne.Size{Height: 40, Width: 1020},
			NewHeaderLabel("RSA Encoded"),
		),
		container.NewGridWrap(
			fyne.Size{Height: 100, Width: 1020},
			encodedRequestEntryLayout,
		),
	)
}

func NewAESRequestEntriesContainer() *fyne.Container {
	aesRequestEntry, aesRequestEntryLayout := NewRequestEntry(true)
	aesEncodedRequestEntry, aesEncodedRequestEntryLayout := NewRequestEntry(false)

	state.aesRequestEntry = aesRequestEntry
	state.aesEncodedRequestEntry = aesEncodedRequestEntry

	return container.NewVBox(
		container.NewGridWrap(
			fyne.Size{Height: 40, Width: 1020},
			NewHeaderLabel("AES Text"),
		),
		container.NewGridWrap(
			fyne.Size{Height: 100, Width: 1020},
			aesRequestEntryLayout,
		),
		container.NewGridWrap(
			fyne.Size{Height: 40, Width: 1020},
			NewHeaderLabel("AES Encoded"),
		),
		container.NewGridWrap(
			fyne.Size{Height: 100, Width: 1020},
			aesEncodedRequestEntryLayout,
		),
	)
}

func NewRequestButtonsContainer() *fyne.Container {

	sendRawButton := widget.NewButton("Encrypt raw", sendRawData)
	sendJsonButton := widget.NewButton("Encrypt JSON", sendJsonData)

	return container.NewGridWithColumns(2, sendRawButton, sendJsonButton)
}

func NewAESRequestButtonsContainer() *fyne.Container {
	encryptRawButton := widget.NewButton("Encrypt raw", sendAESRawData)

	return container.NewGridWithColumns(1, encryptRawButton)
}
