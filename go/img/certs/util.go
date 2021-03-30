package certs

import (
	"encoding/asn1"
	"strconv"
	"strings"
)

func ParseOID(oid string) asn1.ObjectIdentifier {
	ret := asn1.ObjectIdentifier{}
	for _, num := range strings.Split(oid, ".") {
		actNum, _ := strconv.ParseInt(num, 10, 64)
		ret = append(ret, int(actNum))
	}
	return ret
}
