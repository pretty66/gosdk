package gosdk

import (
	"github.com/dgrijalva/jwt-go"
	"io"
)

const VERSION = "0.2.4"

/**
 * UA标识
 */
const USER_AGENT = "ITFARM-GO-CLIENT"

/**
 * 最大并发数
 */
const MAX_CONCURRENCY = 512

/**
 * 默认并发送
 */
const DEFAULT_CONCURRENCY = 5

/**
 * 默认连接超时时间
 */
const CONNECT_TIMEOUT = 2.0

/**
 * 默认请求超时时间
 */
const TIMEOUT = 3.0

/*
 * 支持的请求方法
 */
//const ALLOW_METHODS[7] ={"get", "delete", "head", "options", "patch", "post", "put"}
var ALLOW_METHODS = []string{"get", "delete", "head", "options", "patch", "post", "put"}

const CONTENT_TYPE_FORM = "application/x-www-form-urlencoded"
const CONTENT_TYPE_JSON = "application/json"
const CONTENT_TYPE_MULTIPART = "multipart/form-data"

const GATEWAY_SERVICE_KEY = "GATEWAY_HOST_SERVICE"

const APP_SECRET_MAP_KEY = "APP_SECRETS_MAP"

const DATA_CHANNEL = "IDG_CHANNELS"

const FROM_APPID_KEY = "from_appid"

const FROM_APPKEY_KEY = "from_appkey"

const FROM_CHANNEL_KEY = "from_channel"

const TO_APPID_KEY = "appid"

const TO_APPKEY_KEY = "appkey"

const TO_CHANNEL = "channel"

const TO_CHANNEL_ALIAS = "alias"

const ACCOUNT_ID_KEY = "account_id"

const SUB_ORG_KEY_KEY = "sub_org_key"

const USER_INFO_KEY = "user_info"

const CALL_STACK_KEY = "call_stack"

const DEFAULT_CHANNEL_ALIAS = "test"

const ISS = "ItfarmGoSdk"

const (
	KONG_PROXY = "KONG_PROXY"
	/*HEADER_APPID   = "x-appid"
	HEADER_APPKEY  = "x-appkey"
	HEADER_CHANNEL = "x-channel"*/
	// 读取请求头
	SELF_APPID_KEY   = "x-appid" // X-Appid
	SELF_APPKEY_KEY  = "x-appkey"
	SELF_CHANNEL_KEY = "x-channel"

	REGISTER_APPID = "xrpkalflbedhowhju6cqszg0p73zd8qu"
)

type fileStruct struct {
	fileKey  string
	fileName string
	file     io.Reader
}

type MyClaimsForRequest struct {
	FromAppid   string              `json:"from_appid"`
	FromAppkey  string              `json:"from_appkey"`
	FromChannel string              `json:"from_channel"`
	Appid       string              `json:"appid"`
	Appkey      string              `json:"appkey"`
	Channel     string              `json:"channel"`
	Alias       string              `json:"alias"`
	AccountId   string              `json:"account_id"`
	SubOrgKey   string              `json:"sub_org_key"`
	UserInfo    map[string]string   `json:"user_info"`
	CallStack   []map[string]string `json:"call_stack"`
	jwt.StandardClaims
}

type MyClaimsForChainRequest struct {
	AccountId string              `json:"account_id"`
	SubOrgKey string              `json:"sub_org_key"`
	UserInfo  map[string]string   `json:"user_info"`
	CallStack []map[string]string `json:"call_stack"`
	jwt.StandardClaims
}
