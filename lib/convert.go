/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: convert.go
 * @Time: 2022/5/9 12:24
 **/

package lib

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
)

// JsonToMap Convert json string to map
func JsonToMap(jsonStr string) map[string]string {
	mapper := make(map[string]string)
	err := json.Unmarshal([]byte(jsonStr), &mapper)
	if err != nil {
		return nil
	}
	return mapper
}

// ConvertIP Find IP Address
func ConvertIP(ip string) string {
	reg, _ := regexp.Compile(`\d+\.\d+\.\d+\.\d+`)
	return string(reg.Find([]byte(ip)))
}

// EncodeMD5 Convert string to md5
func EncodeMD5(s string) string {
	hash := md5.New()
	hash.Write([]byte(s))
	md5Str := hex.EncodeToString(hash.Sum(nil))
	return md5Str
}

// CheckIP Check whether the entered IP address is valid
func CheckIP(ip string) bool {
	if m, _ := regexp.MatchString("^(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\.(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\.(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\.(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)$", ip); !m {
		return false
	}
	return true
}

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
