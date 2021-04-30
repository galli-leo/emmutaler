package rawasn1

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshal(t *testing.T) {
	assert := assert.New(t)
	test_img_file := "../../../../img/test.img4"
	data, err := os.ReadFile(test_img_file)
	assert.NoError(err)
	res, err := Unmarshal(data)
	assert.NoError(err)
	assert.EqualValues([]byte{0x30}, res.Tag)
}
