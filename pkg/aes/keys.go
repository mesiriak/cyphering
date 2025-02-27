package aes

type Key struct {
	SingleKey string
}

func GenerateKeys(bitSize int) (*Key, error) {
	return &Key{SingleKey: ""}, nil
}
