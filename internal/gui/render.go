package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"strconv"
)

func NewHeaderLabel(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.Alignment = fyne.TextAlignCenter
	label.TextStyle = fyne.TextStyle{Bold: true}

	return label
}

func NewKeyEntry(title string) (*widget.Entry, *fyne.Container) {
	// Creates entry title label, entry and copy entry text button.
	keyLabel := NewHeaderLabel(title)
	keyEntry := widget.NewEntry()

	keyEntry.Disable()

	copyKeyEntryButton := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		state.window.Clipboard().SetContent(keyEntry.Text)
	})

	keyEntryLayout := container.NewBorder(
		keyLabel,
		nil,
		nil,
		nil,
		keyEntry, container.NewHBox(layout.NewSpacer(), copyKeyEntryButton),
	)

	keyEntryLayout.Resize(fyne.NewSize(340, 40))
	keyEntry.Resize(fyne.NewSize(300, 40))

	return keyEntry, keyEntryLayout
}

func NewKeyBitSizeSelect(choices []string) *widget.Select {
	keyBitSizeSelect := widget.NewSelect(
		choices,
		func(s string) {
			state.clearKeysEntries()
			state.bitSize, _ = strconv.Atoi(s)
		},
	)
	keyBitSizeSelect.PlaceHolder = "Enter key bit size (2 ^ n)..."

	return keyBitSizeSelect
}

func NewRequestEntry(active bool) (*widget.Entry, *fyne.Container) {
	requestEntry := widget.NewMultiLineEntry()
	requestEntry.Wrapping = fyne.TextWrapWord

	if !active {
		requestEntry.Disable()
	}

	return requestEntry, container.NewMax(requestEntry)
}
