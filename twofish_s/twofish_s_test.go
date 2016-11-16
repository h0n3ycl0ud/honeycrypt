package twofish_s
import "testing"

func TestCBC_E(b *testing.T){
  pt := "Hello, world!"
  key := "hello, world1"
  iv := "ABCdef1234567890"
  CBC_E(pt,key,iv,false)
}
