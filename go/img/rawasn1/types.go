package rawasn1

type DERItem struct {
	Tag      []byte
	Length   []byte
	Contents []byte
	Children []*DERItem
}
