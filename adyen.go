package adyen



import (

	"crypto/hmac"

	"crypto/sha256"
	"encoding/hex"
	"encoding/base64"
	"log"

	"net/url"

	"sort"
	"strings"
)


// SignStr generates the signing string with the required parameters in the specified (sorted by keys) order
// with escaped characters and joined with ":"
func SignStr(v url.Values) string {

	var keys []string
	var keysSorted []string
    for k := range v {
        keys = append(keys, k)
    }

    sort.Strings(keys)
    for _, k := range keys {
    	keysSorted = append(keysSorted,  escapeVal( k ) )
    }

    for _, k := range keys {
    	keysSorted = append(keysSorted,  escapeVal( v.Get(k) ) )
    }

    return strings.Join(keysSorted, ":")
}

// Signature generates the HMAC signature from the signing string using SHA-256
// It returns the base64 encoded signature to be set as "merchantSig".
func Signature(key string, signStr string) string {

	keySign, err := hex.DecodeString(key)

	if err != nil {
		log.Printf("Error in DecodeString: %s", err.Error() )
	}

	mac := hmac.New(sha256.New, keySign)
	mac.Write([]byte(signStr))
	sum := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(sum)
}

func escapeVal( str string ) string {

	a := strings.Replace(str, "\\", "\\\\", -1)
	b := strings.Replace(a, ":", "\\:", -1)

	return b
}
