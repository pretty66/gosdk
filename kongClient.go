package gosdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/pretty66/gosdk/cienv"
	"github.com/pretty66/gosdk/errno"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type idn struct {
	appId   string
	appKey  string
	channel string
	alias   string
	version string
}

type kongClient struct {
	header          http.Header
	currentInfo     idn
	targetInfo      idn
	proxy           string
	server          Server
	isInit          bool
	timeout         time.Duration // s
	connectTimeout  time.Duration // s
	callStacks      []map[string]string
	subOrgKey       string
	accountId       string
	baseAccountInfo map[string]string
	consumer        string
	secret          []byte
	token           string // 本次请求需要传递过去的token
	superAccountId  string
	sw              sync.Mutex
}

func NewKongClient(header http.Header) (Client, error) {
	client := &kongClient{
		baseAccountInfo: map[string]string{},
		callStacks:      []map[string]string{},
	}

	err = client.initProxy()
	if err != nil {
		return nil, err
	}

	client.timeout = TIMEOUT * time.Second
	client.connectTimeout = CONNECT_TIMEOUT * time.Second

	err = client.ParseTokenInfo(header)
	return client, err
}

// 调用链为空则是app调用
func (c *kongClient) IsCallerApp() bool {
	return len(c.callStacks) == 0
}

func (c *kongClient) initProxy() error {
	if c.proxy == "" {
		c.proxy = cienv.GetEnv(GATEWAY_SERVICE_KEY)
		if c.proxy == "" {
			return errno.GATEWAY_MISSING
		}
		c.proxy = strings.Trim(c.proxy, "\t\n\r /")
		c.proxy = strings.ReplaceAll(c.proxy, "kong:", "")
	}
	return nil
}

func (c *kongClient) ParseTokenInfo(head http.Header) error {
	var err error
	c.server, err = GetServerInstance(head)
	c.header = head
	if err != nil {
		return err
	}
	if c.server.tokenExist {
		/*claims, err := c.server.GetTokenData()
		if err != nil {
			return err
		}*/
		err = c.parseClaims()
		if err != nil {
			return err
		}
		c.isInit = true
	}

	return nil
}

func (c *kongClient) parseClaims() error {
	if c.currentInfo.appId == "" {
		c.currentInfo.appId = c.server.GetAppId()
	}
	if c.currentInfo.appKey == "" {
		c.currentInfo.appKey = c.server.GetAppKey()
	}
	if c.currentInfo.channel == "" {
		c.currentInfo.channel = c.server.GetChannel()
	}

	if c.currentInfo.appId == "" || c.currentInfo.appKey == "" || c.currentInfo.channel == "" {
		return errno.REQUEST_HEADER_ERROR
	}
	c.callStacks = c.server.GetCallStack()
	c.accountId = c.server.GetAccountId()
	c.subOrgKey = c.server.GetSubOrgKey()
	c.baseAccountInfo = c.server.GetUserInfo()
	c.superAccountId = c.server.GetSuperAdmin()
	return nil
}

func (c *kongClient) SetProxy(proxy string) error {
	c.proxy = strings.TrimRight(proxy, "\\ /")
	return nil
}

func (c *kongClient) SetAccountId(accountId string) error {
	if accountId != "" {
		c.accountId = accountId
	}
	return nil
}

func (c *kongClient) SetSubOrgKey(subOrgKey string) error {
	if subOrgKey != "" {
		c.subOrgKey = subOrgKey
	}
	return nil
}

func (c *kongClient) generateStackApp(appId, appKey, channel, version string) map[string]string {
	return map[string]string{
		"appid":   appId,
		"appkey":  appKey,
		"channel": channel,
		"alias":   "",
		"version": version,
	}
}

func (c *kongClient) SetAppInfo(appId, appKey, channel, version string) error {
	if !c.IsCallerApp() {
		return errno.CAN_NOT_CALL_THIS_METHOD
	}
	if appId == "" || appKey == "" || channel == "" {
		return errno.REQUEST_SETING_ERROR
	}
	c.currentInfo.appId = appId
	c.currentInfo.appKey = appKey
	c.currentInfo.channel = channel
	c.callStacks = []map[string]string{}
	c.callStacks = append(c.callStacks, c.generateStackApp(appId, appKey, channel, version))
	c.isInit = true
	return nil
}

func (c *kongClient) SetService(proxyUrl string) *kongClient {
	if proxyUrl != "" {
		c.proxy = proxyUrl
	}
	return c
}

func (c *kongClient) SetAsSuperAdmin() {
	c.superAccountId = SUPER_ADMIN_ACCOUNT_ID
}

func (c *kongClient) GetSuperAdmin() string {
	return c.server.GetSuperAdmin()
}

func (client *kongClient) SetUserInfo(userInfo map[string]string) error {
	if !client.IsCallerApp() {
		return errno.CAN_NOT_CALL_THIS_METHOD
	}
	if userInfo["name"] != "" {
		client.baseAccountInfo["name"] = userInfo["name"]
	}
	if userInfo["avatar"] != "" {
		client.baseAccountInfo["avatar"] = userInfo["avatar"]
	}
	return nil
}

func (client *kongClient) SetTimeout(timeout time.Duration) error {
	client.timeout = timeout
	if _httpClient != nil {
		tr := &http.Transport{
			TLSHandshakeTimeout:   client.connectTimeout,
			ResponseHeaderTimeout: client.timeout,
		}
		_httpClient.Transport = tr
	}
	return nil
}

func (client *kongClient) SetConnectTimeout(timeout time.Duration) error {
	client.connectTimeout = timeout
	if _httpClient != nil {
		tr := &http.Transport{
			TLSHandshakeTimeout:   client.connectTimeout,
			ResponseHeaderTimeout: client.timeout,
		}
		_httpClient.Transport = tr
	}
	return nil
}

func (c *kongClient) makeConsumer() {
	c.consumer = MakeConsumer(c.currentInfo.appId, c.currentInfo.appKey, c.currentInfo.channel)
	// todo secret
	c.secret = []byte(MakeSecret(c.currentInfo.appId, c.currentInfo.appKey, c.currentInfo.channel))
}

func (c *kongClient) makeUrl(serviceName, targetChannelAlias, api string) string {
	targetChannelAlias = strings.Trim(targetChannelAlias, "\\ /")
	api = strings.Trim(api, "\\ /")
	route := MakeRoute(c.currentInfo.appKey, c.currentInfo.channel, serviceName, targetChannelAlias)
	c.targetInfo.appId = serviceName
	c.targetInfo.alias = targetChannelAlias
	return c.proxy + "/" + route + "/" + api
}

func (c *kongClient) makeUrlForInstance(targetAppId, targetAppKey, targetChannel, api string) string {
	api = strings.Trim(api, "\\ /")
	route := MakeInstanceRoute(c.currentInfo.appId, c.currentInfo.appKey, c.currentInfo.channel, targetAppId, targetAppKey, targetChannel)
	c.targetInfo.appId = targetAppId
	c.targetInfo.appKey = targetAppKey
	c.targetInfo.channel = targetChannel
	return c.proxy + "/" + route + "/" + api
}

func (c *kongClient) getSigner() *jwt.SigningMethodHMAC {
	return jwt.SigningMethodHS256
}

// 组合token数据
func (c *kongClient) claimsForThisRequest() MyClaimsForRequest {
	return MyClaimsForRequest{
		FromAppid:      c.currentInfo.appId,
		FromAppkey:     c.currentInfo.appKey,
		FromChannel:    c.currentInfo.channel,
		Alias:          c.targetInfo.alias,
		AccountId:      c.accountId,
		SubOrgKey:      c.subOrgKey,
		UserInfo:       c.baseAccountInfo,
		SuperAccountId: c.superAccountId,
		CallStack: append(c.callStacks, map[string]string{
			"appid":   c.targetInfo.appId,
			"appkey":  c.targetInfo.appKey,
			"channel": c.targetInfo.channel,
			"alias":   c.targetInfo.alias,
		}),
	}
}

func (c *kongClient) MakeToken(claims MyClaimsForRequest, expire int64) string {
	now := time.Now().Unix()
	if c.consumer == "" {
		c.makeConsumer()
	}
	claims.ExpiresAt = time.Now().Unix() + expire
	claims.Issuer = c.consumer
	claims.IssuedAt = now
	claims.NotBefore = now
	token := jwt.NewWithClaims(c.getSigner(), claims)
	result, _ := token.SignedString(c.secret)
	return result
}

// 生成一个指定时间过期的token
func (c *kongClient) ReInitCurrentTokenWithSeconds(seconds int64) string {
	claims := MyClaimsForRequest{
		Appid:          c.currentInfo.appId,
		Appkey:         c.currentInfo.appKey,
		Channel:        c.currentInfo.channel,
		SubOrgKey:      c.subOrgKey,
		AccountId:      c.accountId,
		SuperAccountId: c.superAccountId,
		UserInfo:       c.baseAccountInfo,
		CallStack:      c.callStacks,
	}
	return c.MakeToken(claims, seconds)
}

func (c *kongClient) checkParam(method, contentType string) error {
	method = strings.ToLower(method)
	if !In_array(method, ALLOW_METHODS) {
		return errno.METHOD_NOT_ALLOWED
	}

	if !In_array(contentType, []string{CONTENT_TYPE_FORM, CONTENT_TYPE_JSON, CONTENT_TYPE_MULTIPART}) {
		return errno.CONTENT_TYPE_ERROR
	}
	return nil
}

// todo 后续做成连接池并保持和网关长连接
var _httpClient *http.Client

func (c *kongClient) getHttpClient() *http.Client {
	if _httpClient == nil {
		tr := &http.Transport{
			TLSHandshakeTimeout:   c.connectTimeout,
			ResponseHeaderTimeout: c.timeout,
		}
		_httpClient = &http.Client{
			Transport: tr,
		}

		// 解决 80端口重定向到443后 鉴权信息被清除
		_httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if c.header.Get("Authorization") != "" {
				req.Header.Set("Authorization", c.header.Get("Authorization"))
			}
			return nil
		}
	}
	return _httpClient
}

func (c *kongClient) parseBody(
	method,
	reqUrl string,
	data map[string]interface{},
	contentType string,
	file *fileStruct,
) (req *http.Request, err error) {
	// todo 多文件上传
	method = strings.ToUpper(method)

	switch contentType {
	case CONTENT_TYPE_FORM:
		theData := url.Values{}
		for k, v := range data {
			theData.Set(k, fmt.Sprint(v))
		}
		body := strings.NewReader(theData.Encode())
		req, err = http.NewRequest(method, reqUrl, body)
		if err != nil {
			err = errno.REQUEST_SETING_ERROR.Add(err.Error())
			return
		}
		req.Header.Set("Content-Type", CONTENT_TYPE_FORM)
	case CONTENT_TYPE_JSON:
		bytesData, err := json.Marshal(data)
		if err != nil {
			return nil, errno.JSON_ERROR.Add(err.Error())
		}
		body := bytes.NewReader(bytesData)
		req, err = http.NewRequest(method, reqUrl, body)
		if err != nil {
			err = errno.REQUEST_SETING_ERROR.Add(err.Error())
			return req, err
		}
		req.Header.Set("Content-Type", CONTENT_TYPE_JSON)

	case CONTENT_TYPE_MULTIPART:
		buff := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(buff)
		// 写入其他参数
		for k, v := range data {
			err := bodyWriter.WriteField(k, fmt.Sprint(v))
			if err != nil {
				return nil, errno.DATA_WRONG_TYPE.Add(err.Error())
			}
		}
		if file != nil {
			// 写入文件
			fileWriter, err := bodyWriter.CreateFormFile(file.fileKey, file.fileName)
			if err != nil {
				return nil, errno.SDK_ERROR.Add(err.Error())
			}

			_, err = io.Copy(fileWriter, file.file)
			if err != nil {
				return nil, errno.SDK_ERROR.Add(err.Error())
			}
		}
		req, err = http.NewRequest(method, reqUrl, buff)
		if err != nil {
			err = errno.REQUEST_SETING_ERROR.Add(err.Error())
			return
		}
		req.Header.Set("Content-Type", bodyWriter.FormDataContentType())
	}
	return
}

func (c *kongClient) Exec(
	method,
	reqUrl string,
	data map[string]interface{},
	contentType string,
	file *fileStruct,
) (out []byte, err error) {
	req, err := c.parseBody(method, reqUrl, data, contentType, file)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", USER_AGENT+"/"+VERSION)
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	realIp := c.server.GetHeader("x-real-ip")
	if realIp != "" {
		req.Header.Set("x-real-ip", realIp)
	}
	traceid := c.server.GetHeader("x-b3-traceid")
	sampled := c.server.GetHeader("x-b3-sampled")
	if traceid != "" && sampled == "1" {
		req.Header.Set("x-b3-traceid", traceid)
		req.Header.Set("x-b3-sampled", sampled)
	}

	resp, err := c.getHttpClient().Do(req)
	if err != nil {
		err = errno.REQUEST_SETING_ERROR.Add(err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		out, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			err = errno.RESPONSE_OTHER.Add(err.Error())
		}
	} else {
		err = requestError(resp)
	}
	return
}

func (c *kongClient) Call(
	serviceName,
	method,
	api string,
	data map[string]interface{},
	channelAlias,
	contentType string,
	file *fileStruct,
) (out []byte, err error) {
	if !c.isInit {
		err = errno.SDK_NOT_INITED
		return
	}
	err = c.checkParam(method, contentType)
	if err != nil {
		return
	}
	// 编译请求链接的uri
	reqUrl := c.makeUrl(serviceName, channelAlias, api)
	// 获取token数据
	claims := c.claimsForThisRequest()
	// 编译token
	c.token = c.MakeToken(claims, 60)

	out, err = c.Exec(method, reqUrl, data, contentType, file)
	return
}

func (client *kongClient) UploadFile(
	appId string,
	api string,
	files *fileStruct,
	data map[string]interface{},
	channelAlias string) ([]byte, error) {
	return client.Call(appId, "POST", api, data, channelAlias, CONTENT_TYPE_MULTIPART, files)
}

func (c *kongClient) CallByChain(
	chains []map[string]string,
	method string,
	api string,
	data map[string]interface{},
	contentType string,
	files *fileStruct,
) (out []byte, err error) {
	// chain 之前需要初始化，setAppInfo
	if !c.isInit {
		err = errno.SDK_NOT_INITED
		return
	}
	if len(chains) < 2 {
		err = errno.INVALID_PARAM.Add("Invalid chains input")
		return
	}
	if chains[0]["appid"] != c.callStacks[0]["appid"] || chains[0]["appkey"] != c.callStacks[0]["appkey"] || chains[0]["channel"] != c.callStacks[0]["channel"] {
		err = errno.CHAIN_INVALID
		return
	}
	chainData := FormatChains(chains)
	targetAppId := chainData[len(chainData)-1].Appid
	targetChannelAlias := MakeChains(chainData)
	// 验证是否第一次调用，去注册中心注册调用关系
	err = c.checkIsFirstRequest(chainData, targetChannelAlias)
	if err != nil {
		return
	}
	// 请求链接
	api = c.makeUrl(targetAppId, targetChannelAlias, api)
	// token中只有自身和目标服务
	claims := c.claimsForThisRequest()
	// 编译token
	c.token = c.MakeToken(claims, 60)
	out, err = c.Exec(method, api, data, contentType, files)
	return
}

func (c *kongClient) checkIsFirstRequest(chains []chain, hashStr string) error {
	if _cache.Get(hashStr) != "" {
		return nil
	}
	path := os.TempDir() + "/data"
	file := "sdk-cache.json"
	if !IsFileExist(path) {
		err := os.Mkdir(path, 0777)
		if err != nil {
			return errno.SDK_ERROR.Add(err.Error())
		}
	}
	path = path + "/" + file
	cacheData := map[string]string{}
	if IsFileExist(path) {
		cacheContent, err := FileGetContents(path)
		if err != nil {
			return errno.SDK_ERROR.Add(err.Error())
		}
		// json 字符串
		if len(cacheContent) > 0 {
			err = json.Unmarshal(cacheContent, &cacheData)
			if err != nil {
				return errno.SDK_ERROR.Add(err.Error())
			}
			if _, ok := cacheData[hashStr]; ok {
				return nil
			}
		}
	}
	// todo 暂时无法保证map顺序
	data := map[string]interface{}{}
	for k, v := range chains {
		data[fmt.Sprintf("chains[%d][appid]", k)] = v.Appid
		data[fmt.Sprintf("chains[%d][appkey]", k)] = v.Appkey
		data[fmt.Sprintf("chains[%d][channel]", k)] = v.Channel
		if v.Alias != "" {
			data[fmt.Sprintf("chains[%d][alias]", k)] = v.Alias
		}
	}
	// 没有已经缓存的记录则查询注册中心
	api := "main.php/json/deploy/checkHostByChain"
	res, err := c.Call(REGISTER_APPID, "POST", api, data, DEFAULT_CHANNEL_ALIAS, CONTENT_TYPE_FORM, nil)
	if err != nil {
		return errno.SDK_ERROR.Add(err.Error())
	}
	out := map[string]interface{}{}
	err = json.Unmarshal(res, &out)
	if err != nil {
		return errno.JSON_ERROR.Add(err.Error())
	}
	state, ok := out["state"]
	if ok && state.(float64) != 1 {
		return errno.CHAIN_INVALID.Add(out["msg"].(string))
	}
	_cache.Set(hashStr, "1", 0)
	cacheData[hashStr] = "1"
	cacheDataByte, err := json.Marshal(cacheData)
	if err != nil {
		return errno.JSON_ERROR.Add(err.Error())
	}
	FilePutContents(path, cacheDataByte)
	return nil
}

func (c *kongClient) CallServiceInstance(appId,
	appKey,
	channel,
	method,
	api string,
	data map[string]interface{},
	contentType string,
	file *fileStruct) (out []byte, err error) {
	if appId == "" || appKey == "" || channel == "" {
		return nil, errno.INVALID_PARAM.Add("Appid ,appkey can not be null or empty string ,channel can not be null")
	}
	if !c.isInit {
		return nil, errno.INVALID_PARAM.Add("The sdk is not full inited , can not process this request")
	}
	err = c.checkParam(method, contentType)
	if err != nil {
		return
	}
	// 编译请求链接的uri
	reqUrl := c.makeUrlForInstance(appId, appKey, channel, api)
	// 获取token数据
	claims := c.claimsForThisRequest()
	// 编译token
	c.token = c.MakeToken(claims, 60)

	out, err = c.Exec(method, reqUrl, data, contentType, file)
	return
}

/**
 * 调用setToken 之前先调用 SetCurrentInfo
 */
func (client *kongClient) SetToken(tokenString string) error {
	if tokenString == "" {
		return nil
	}
	if client.currentInfo.appId == "" || client.currentInfo.appKey == "" {
		return errno.SDK_NOT_INITED.Add("Should set current info by call setCurrentInfo")
	}

	client.makeConsumer()
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (i interface{}, e error) {
		return token, nil
	})
	tokenIssuer := token.Claims.(jwt.MapClaims)["iss"]
	isTokenIssuer := false
	if tokenIssuer == client.consumer {
		isTokenIssuer = true
	}
	if isTokenIssuer && getSigner().Verify(tokenString, token.Signature, client.secret) == nil {
		/*originClaims := token.Claims.(jwt.MapClaims)
		claims := make(map[string]interface{})
		for k, v := range originClaims {
			claims[k] = v
		}*/
		err = client.server.SetToken(tokenString)
		if err != nil {
			return err
		}
		err := client.parseClaims()
		if err != nil {
			return err
		}
		client.isInit = true
		return err
	}
	return nil
}

func (c *kongClient) GetServer() Server {
	return c.server
}
