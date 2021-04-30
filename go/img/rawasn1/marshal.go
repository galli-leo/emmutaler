package rawasn1

func Marshal(item *DERItem) []byte {
	return marshal(item)
}

func marshal(item *DERItem) []byte {
	ret := []byte{}
	ret = append(ret, item.Tag...)
	ret = append(ret, item.Length...)
	if len(item.Children) > 0 {
		for _, child := range item.Children {
			ret = append(ret, marshal(child)...)
		}
	} else {
		ret = append(ret, item.Contents...)
	}
	return ret
}
