package img

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReceiverFunc(t *testing.T) {
	assert := assert.New(t)
	testVal := &RecvTest{}
	m := NewMut(testVal)
	m.AddMut((*RecvTest).ChangeVal)
	assert.NoError(m.Gen())
	assert.EqualValues(42, testVal.Val)
}
