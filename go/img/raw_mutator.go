package img

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/galli-leo/emmutaler/img/rawasn1"
	fuzz "github.com/google/gofuzz"
)

type iterFunc func(item *rawasn1.DERItem)

func RawIter(item *rawasn1.DERItem, fn iterFunc) {
	fn(item)
	for _, child := range item.Children {
		RawIter(child, fn)
	}
}

func GenMutations(data []byte, outDir string) {
	parsed, _ := rawasn1.Unmarshal(data)
	numGens := 1000
	fuzzer := fuzz.New()
	// first get num items
	items := 0
	RawIter(parsed, func(item *rawasn1.DERItem) {
		items++
	})

	for i := 0; i < numGens; i++ {
		numConc := rand.Intn(10) + 1
		parsed, _ := rawasn1.Unmarshal(data)
		filename := fmt.Sprintf(`asn1_mut_%04d.img4`, i)
		for k := 0; k < numConc; k++ {
			randNum := rand.Intn(items)
			var randItem *rawasn1.DERItem
			curr := 0
			RawIter(parsed, func(item *rawasn1.DERItem) {
				if curr == randNum {
					randItem = item
				}
				curr++
			})
			conts := 3
			if len(randItem.Children) > 0 {
				conts = 2
			}
			field := rand.Intn(conts)
			if field == 0 {
				fuzzer.Fuzz(&randItem.Tag)
			} else if field == 1 {
				fuzzer.Fuzz(&randItem.Length)
			} else if field == 2 {
				fuzzer.Fuzz(&randItem.Contents)
			} else {
				panic("fuck you")
			}
		}

		result := rawasn1.Marshal(parsed)
		os.WriteFile(filepath.Join(outDir, filename), result, 0777)
	}
}
