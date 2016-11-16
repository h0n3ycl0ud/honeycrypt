/**
* Provides wrappers for the twofish package that facilitate
* easy use on large amounts of data (as well as on data
* types that are slightly more 'friendly' than []byte :)
*
**/
package twofish_s

import (
  "fmt"
  "crypto/rand"
  "honeycrypt/twofish"
  "golang.org/x/crypto/sha3"
  "encoding/base64"
)
/*
CBC_E(...)

       **DO NOT USE nil FOR THE IV**
       Unless you know it's ok....
       This is a path of great peril.
       Take special note that, rather
       than spitting an error if the IV                  <<<(((btws go's crypto/rand is fine, go ahead and use a nil iv :* ~p)))
       isn't of an appropriate length,
       this func will hash your value
       then use the magic-hat property
       of keccak to get 16 bytes that
       are still only as random as your
       ability not to re-use an IV/key pair. We clear? kthx <3 (~):} ~p00h

pt - the plaintext to be encrypted
key - the key to be used (it will be hashed to the appropriate length)
iv - the initialization vector. If nil, it will be generated
hex - if not `true`, character values will be used. If `true`, the
      initialization vector as well as the key (*not* the plaintext)
      strings will be parsed as hex values, ie 'ff' or 'FF' -> 255
      but not including a 0x i.e.
      FF00FF00AA00


returns:
err - boolean - did we fail? probably not...
*/
// %x prints a hex byte
func CBC_E(pt string, key string, iv string, hex bool) (bool, string){

  //first encode it so we can buffer it without worring about whose
  //padding is whose
  bpt := []byte(pt)
  pt = base64.StdEncoding.EncodeToString(bpt)
  bpt = []byte(pt)
  fmt.Println(pt)

  //then calculate how many blocks we have and pad our buffers here "{}"
  nblocks := (int)(len(bpt) / 16)
  blocks := make([][]byte, nblocks)
  for i := range blocks{
    blocks[i] = make([]byte, 16)
  }
  ciphertext := make([]byte, len(pt))


  err, c := twofish.NewCipher(bpt)
  if(err != nil){
    return true, ""
  }
  hash_slinging_slasher := sha3.New256()
  var bkey [32]byte
  var biv [16]byte

  pool := make([]byte, 10000)
  rand.Read(pool)
  if(iv == ""){
    for i := 0; i < 42; i++{
      pool = hash_slinging_slasher.Sum(pool)
    }
    sh := sha3.Sum256(pool)
    for j:=0;j<16;j++{
      biv[j] = sh[j]
    }
  }else{
    if(len(iv) != 16){
      sh := sha3.Sum256([]byte(iv))
      for j:=0;j<16;j++ {
        biv[j] = sh[j]
      }
    }else{
      for j:=0;j<16;j++ {
        biv[j] = iv[j]
      }
    }
  }


  padding := 16-(len(bpt)%16)
  for i:=0;i<padding;i++{
    pt += "~"
    bpt = append(bpt, 0)
  }

  for i,j := range blocks{
    ########
  }
  fmt.Println("IV:")
  fmt.Println(biv)
  fmt.Println("Before: ")
  fmt.Println(blocks[0])
  for i:=0;i<16;i++{
    blocks[0][i] ^= biv[i]
  }
  fmt.Println("After: ")
  fmt.Println(blocks[0])

  fmt.Println("IV:")
  fmt.Println(biv)
  fmt.Println("Plaintext:")
  fmt.Println(pt)
  fmt.Printf("Ciphertext: (%d blocks + %d (%d chars))\n", nblocks,padding,len(bpt))
  _ = c
  _ = bkey
  sct := "Canary"
  _ = blocks
  _ = ciphertext
  return false, sct
}
