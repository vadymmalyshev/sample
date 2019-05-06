package auth

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"git.tor.ph/hiveon/idp/config"
	"github.com/sirupsen/logrus"
)

func SetAccessTokenCookie(w http.ResponseWriter, token string) {
	var value string

	splitToken := strings.Split(token, " ")

	if len(splitToken) < 2 && splitToken[0] != "" {
		value = splitToken[0]
	}
	if len(splitToken) > 1 {
		value = splitToken[1]
	}

	cookieDomain, _ := config.GetCookieDomain()

	cookie := http.Cookie{
		Name:   "Authorization",
		Value:  fmt.Sprintf("Bearer %s", value),
		Domain: cookieDomain,
		Path:   "/",
	}

	http.SetCookie(w, &cookie)
}

func ToMap(in interface{}, tag string) (map[string]interface{}, error) {
	out := make(map[string]interface{})

	v := reflect.ValueOf(in)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// we only accept structs
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("ToMap only accepts structs; got %T", v)
	}

	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		// gets us a StructField
		fi := typ.Field(i)
		if tagv := fi.Tag.Get(tag); tagv == "" {
			// set key of map to value in struct field
			if fi.Name == "TOTPSecretKey" {
				out["Enabled2fa"] = false
				if value := v.Field(i).String(); value != "" {
					out["Enabled2fa"] = true
				}
				continue
			}
			out[fi.Name] = v.Field(i).Interface()
		}
	}
	return out, nil
}

func stateTokenGenerator() (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		logrus.Errorf("crypto/rand failed: %v", err)
		return "", err
	}

	return fmt.Sprintf("%x", b), nil
}
