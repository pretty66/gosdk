package gosdk

import (
	"gosdk/cache"
	"gosdk/cienv"
	"net/http"
	"strings"
	"time"
)

type Client interface {
	IsCallerApp() bool
	SetProxy(proxy string) error
	SetAccountId(accountId string) error
	SetSubOrgKey(subOrgKey string) error
	SetAppInfo(appId, appKey, channel, version string) error
	SetUserInfo(userInfo map[string]string) error
	SetTimeout(timeout time.Duration) error
	SetConnectTimeout(timeout time.Duration) error
	MakeToken(claims MyClaimsForRequest, expire int64) string
	Call(appId, method, api string, data map[string]interface{}, channelAlias, contentType string, files *fileStruct) ([]byte, error)
	CallByChain(chains []map[string]string,
		method string,
		api string,
		data map[string]interface{},
		contentType string,
		files *fileStruct,
	) (out []byte, err error)
	CallServiceInstance(appId,
		appKey,
		channel,
		method,
		api string,
		data map[string]interface{},
		contentType string,
		file *fileStruct,
	) (out []byte, err error)
	UploadFile(
		appId string,
		api string,
		files *fileStruct,
		data map[string]interface{},
		channelAlias string,
	) ([]byte, error)
	SetToken(tokenString string) error

	ParseTokenInfo(head http.Header) error
	initProxy() error
	ReInitCurrentTokenWithSeconds(s int64) string
}

var _cache *cache.Cache
var _cli Client
var err error

func GetClientInstance(header http.Header) (Client, error) {
	if _cli != nil {
		return _cli, _cli.ParseTokenInfo(header)
	}
	// 初始化缓存
	if _cache == nil {
		_cache = cache.NewCache(false, 0)
	}
	proxy := cienv.GetEnv(GATEWAY_SERVICE_KEY)
	if proxy != "" {
		if strings.HasPrefix(proxy, "kong:") {
			// kong 代理
			_cli, err = NewKongClient(header)
		}
	}
	if _cli == nil {
		_cli, err = NewOldClient(header)
	}
	return _cli, err
}
