package cienv

import (
	"fmt"
	"github.com/pretty66/gosdk/cache"
	"io/ioutil"
	"os"
)

var _cli = cache.NewCache(true, 600)

func IsFileExist(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func GetEnv(name string) string {
	res := _cli.Get(name)
	if res != "" {
		return res
	}
	basePath := os.Getenv("ENVS_BASE_PATH")
	if basePath != "" {
		filePath := basePath + "/" + name
		if IsFileExist(filePath) {
			data, err := ioutil.ReadFile(filePath)
			if err != nil {
				fmt.Println("get env error", err)
				return ""
			}
			if len(data) > 0 {
				_ = _cli.Set(name, string(data), 0)
				return string(data)
			}
		}
	}
	return os.Getenv(name)
}


func SetEnv(name, val string) error {
	return os.Setenv(name, val)
}