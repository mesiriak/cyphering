package main

import (
	"github.com/mesiriak/cyphering/internal/gui"
	"log"
)

func main() {
	app, err := gui.NewGUI()

	if err != nil {
		log.Fatal(err)
	}

	app.Run()
}
