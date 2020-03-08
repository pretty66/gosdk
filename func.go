package gosdk

import (
	"crypto/md5"
	"encoding/hex"
	"gosdk/errno"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func GetIp() string {
	var ip string
	if os.Getenv("SERVER_ADDR") != "" && !strings.EqualFold(os.Getenv("SERVER_ADDR"), "unknown") {
		ip = os.Getenv("SERVER_ADDR")
	}
	if ip == "" {
		ip = "0.0.0.0"
	}
	//7位-15位，由数字和.组成
	regs, _ := regexp.Compile(`[\d.]{7,15}`)
	str := regs.FindAllString(ip, -1)
	if len(str) > 0 {
		return str[0]
	}
	return ""
}

func GetPort(head http.Header) string {
	if head.Get("SERVER_PORT") != "" {
		return head.Get("SERVER_PORT")
	}
	return "0"
}

func Zipkin_timestamp() string {
	localTime := time.Now().UnixNano()
	return strconv.FormatInt(localTime/1000, 10)
}



func NewMd5(str ...string) string {
	h := md5.New()
	for _, v := range str {
		h.Write([]byte(v))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func NewImplodeMd5(glue string, str ...string) string {
	s := strings.Join(str, glue)
	return NewMd5(s)
}

func In_array(s string, slice []string) bool {
	for _, v := range slice {
		if s == v {
			return true
		}
	}
	return false
}

func FormatChains(chains []map[string]string) []map[string]string {
	out := make([]map[string]string, len(chains))
	for k, v := range chains {
		out[k] = map[string]string{
			"appid":   v["appid"],
			"appkey":  v["appkey"],
			"channel": v["channel"],
		}
		if k != 0 {
			alias, ok := v["alias"]
			if !ok {
				alias, ok = v["channelAlias"]
			}
			out[k]["alias"] = alias
		}
	}
	return out
}


func IsFileExist(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func FileGetContents(path string) (out []byte, err error) {
	if IsFileExist(path) {
		out, err =  ioutil.ReadFile(path)
	}
	return
}

func FilePutContents(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0777)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(content)
	if err != nil {
		return err
	}
	return nil
}


func requestError(response *http.Response) error {
	switch response.StatusCode {
	case 401:
		return errno.RESPONSE_401
	case 403:
		return errno.RESPONSE_403
	case 404:
		body, _ := ioutil.ReadAll(response.Body)
		return errno.RESPONSE_404.SetCode(response.StatusCode, string(body))
	default:
		body, _ := ioutil.ReadAll(response.Body)
		return errno.RESPONSE_OTHER.SetCode(response.StatusCode, string(body))
	}
}
