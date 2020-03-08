package gosdk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
	"strconv"
	"strings"
	"time"
)

type oldClient struct {
	header          http.Header
	services        map[string]string
	timeout         time.Duration // 延迟时间
	connectTimeout  time.Duration // 连接超时时间
	concurrency     int
	token           string
	isTokenIssuer   bool
	accountId       string
	subOrgKey       string
	baseAccountInfo map[string]string
	appSecret       string
	callStacks      []map[string]string
	targetInfo      map[string]string
	currentInfo     map[string]string
	inited          bool
	proxy           string
	server          Server
}

func NewOldClient(header http.Header) (Client, error) {
	client := &oldClient{
		baseAccountInfo: map[string]string{},
		callStacks:      []map[string]string{},
		targetInfo:      map[string]string{},
		currentInfo:     map[string]string{},
		services:        map[string]string{},
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

func (c *oldClient) initProxy() error {
	if c.proxy == "" {
		envProxy := cienv.GetEnv(GATEWAY_SERVICE_KEY)
		if envProxy != "" {
			c.proxy = strings.Trim(envProxy, "\t\n\r /")
		}
	}
	return nil
}

func (client *oldClient) ParseTokenInfo(header http.Header) error {
	client.server, err = GetServerInstance(header)
	if err != nil {
		return err
	}
	client.header = header

	if client.server.tokenExist {
		/*claim, err := server.GetTokenData()
		if err != nil {
			return err
		}*/
		err1 := client.parseClaims()
		client.inited = true
		return err1
	}
	return nil
}

func (c *oldClient) parseClaims() error {
	if c.currentInfo["appid"] == "" {
		c.currentInfo["appid"] = c.server.GetAppId()
	}
	if c.currentInfo["appkey"] == "" {
		c.currentInfo["appkey"] = c.server.GetAppKey()
	}
	if c.currentInfo["channel"] == "" {
		c.currentInfo["channel"] = c.server.GetChannel()
	}

	if c.currentInfo["appid"] == "" || c.currentInfo["appkey"] == "" || c.currentInfo["channel"] == "" {
		return errno.REQUEST_HEADER_ERROR
	}
	c.callStacks = c.server.GetCallStack()
	c.accountId = c.server.GetAccountId()
	c.subOrgKey = c.server.GetSubOrgKey()
	c.baseAccountInfo = c.server.GetUserInfo()
	return nil
}

func (client *oldClient) SetProxy(proxy string) error {
	/*for k, v := range services {
		client.services[k] = strings.TrimRight(v, "/") + "/"
	}
	return nil*/
	client.proxy = strings.TrimRight(proxy, "\\ /")
	return nil
}

func (client *oldClient) SetAccountId(accountId string) error {
	if accountId != "" {
		client.accountId = accountId
	}
	return nil
}

func (client *oldClient) SetUserInfo(userInfo map[string]string) error {
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

func (client *oldClient) IsCallerApp() bool {
	return len(client.callStacks) == 0
}

func (client *oldClient) SetConnectTimeout(timeout time.Duration) error {
	client.connectTimeout = timeout
	return nil
}

func (client *oldClient) SetTimeout(timeOut time.Duration) error {
	client.timeout = timeOut
	return nil
}

func (client *oldClient) SetToken(tokenString string) error {
	if tokenString == "" {
		return nil
	}
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (i interface{}, e error) {
		return token, nil
	})
	tokenIssuer := token.Claims.(jwt.MapClaims)["iss"]
	isTokenIssuer := false
	if tokenIssuer == ISS {
		isTokenIssuer = true
	}
	if isTokenIssuer && getSigner().Verify(tokenString, token.Signature, client.appSecret) == nil {
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
		client.isTokenIssuer = true
		client.inited = true
		return err
	}
	return nil
}

func getSigner() *jwt.SigningMethodHMAC {
	return jwt.SigningMethodHS256
}

func (client *oldClient) SetSubOrgKey(subOrgKey string) error {
	if subOrgKey != "" {
		client.subOrgKey = subOrgKey
	}
	return nil
}

func (client *oldClient) SetAppInfo(appid, appkey, channel, version string) error {
	if !client.IsCallerApp() {
		return errno.CAN_NOT_CALL_THIS_METHOD.Add("This method can only called by first app")
	}
	if appid == "" || appkey == "" {
		return errno.INVALID_PARAM.Add("appid,appkey,channel can not be null and appid,appkey can not be empty")
	}
	client.callStacks = append(client.callStacks, generateStackRow(appid, appkey, string(channel), "", version))
	client.currentInfo["appid"] = appid
	client.currentInfo["appkey"] = appkey
	client.currentInfo["channel"] = channel
	client.inited = true
	return nil
}

func generateStackRow(appid, appkey, channel, alias, version string) map[string]string {
	return map[string]string{"appid": appid, "appkey": appkey, "channel": channel, "alias": alias, "version": version}
}

// 生成一个指定时间过期的token
func (c *oldClient) ReInitCurrentTokenWithSeconds(seconds int64) string {
	claims := MyClaimsForRequest{
		Appid:     c.currentInfo["appid"],
		Appkey:    c.currentInfo["appkey"],
		Channel:   c.currentInfo["channel"],
		SubOrgKey: c.subOrgKey,
		CallStack: c.callStacks,
	}
	return c.MakeToken(claims, seconds)
}

//请求服务
//serviceName 	servicekey
//method		post,get,put
//api			服务的路径
//data			要传递的数据
//channelAlias 	别名，传入空值时为"default"
//contentType	发送请求的类型，空值为"application/x-www-form-urlencoded"
//file			要上传的文件
func (client *oldClient) Call(serviceName string,
	method string,
	api string,
	data map[string]interface{},
	channelAlias string,
	contentType string,
	files *fileStruct) ([]byte, error) {
	if !client.inited {
		return nil, errno.SDK_NOT_INITED.Add("The sdk is not full inited to process the request")
	}
	if channelAlias == "" {
		channelAlias = DEFAULT_CHANNEL_ALIAS
	}
	if contentType == "" {
		contentType = CONTENT_TYPE_FORM
	}
	client.targetInfo["appid"] = serviceName
	err := client.GetChannelDataFromEnv(serviceName, channelAlias)
	if err != nil {
		return nil, err
	}
	claims := client.claimsForThisRequest()
	client.makeToken(claims)
	if data == nil {
		data = make(map[string]interface{})
	}
	return client.Exec(serviceName, method, api, data, contentType, files)
}

var channelDatas = make(map[string]interface{})

func (client *oldClient) GetChannelDataFromEnv(appid, channelAlias string) error {
	if _, ok := channelDatas[client.currentInfo["appkey"]]; !ok {
		channelEnv := os.Getenv(DATA_CHANNEL)
		channelEnv = strings.Trim(channelEnv, `'`)
		if channelEnv != "" {
			channelEnvByte := []byte(channelEnv)
			json.Unmarshal(channelEnvByte, &channelDatas)
		} else {
			return errno.REQUEST_HEADER_ERROR.Add("IDG_CHANNELS is empty")
		}
	}
	appData := map[string]interface{}{}
	var appchannel string
	appkey := ""
	if value, ok := channelDatas[client.currentInfo["appkey"]]; fmt.Sprintf("%T", value) == "map[string]interface {}" && ok {
		appData = channelDatas[client.currentInfo["appkey"]].(map[string]interface{})
	} else {
		return errno.REQUEST_HEADER_ERROR.Add("IDG_CHANNELS parse fail:appkey")
	}
	if value, ok := appData[client.currentInfo["channel"]]; fmt.Sprintf("%T", value) == "map[string]interface {}" && ok {
		appData = appData[client.currentInfo["channel"]].(map[string]interface{})
	} else {
		return errno.REQUEST_HEADER_ERROR.Add("IDG_CHANNELS parse fail:channel")
	}
	if value, ok := appData[appid]; fmt.Sprintf("%T", value) == "map[string]interface {}" && ok {
		appData = appData[appid].(map[string]interface{})
	} else {
		return errno.REQUEST_HEADER_ERROR.Add("IDG_CHANNELS parse fail:to_appid")
	}
	if value, ok := appData[channelAlias]; fmt.Sprintf("%T", value) == "map[string]interface {}" && ok {
		appData = appData[channelAlias].(map[string]interface{})
	} else {
		return errno.REQUEST_HEADER_ERROR.Add("IDG_CHANNELS parse fail:to_channelAlias")
	}
	if value, ok := appData["target_appkey"]; fmt.Sprintf("%T", value) == "string" && ok {
		appkey = appData["target_appkey"].(string)
	} else {
		return errno.REQUEST_HEADER_ERROR.Add("IDG_CHANNELS parse fail:target_appkey")
	}
	if value, ok := appData["target_channel"]; fmt.Sprintf("%T", value) == "float64" && ok {
		appchannel = strconv.FormatFloat(appData["target_channel"].(float64), 'f', -1, 64)
	} else {
		return errno.REQUEST_HEADER_ERROR.Add("IDG_CHANNELS parse fail:target_channel")
	}
	client.targetInfo = generateStackRow(
		appid,
		appkey,
		appchannel,
		channelAlias,
		"")
	return nil
}

func (client *oldClient) claimsForThisRequest() MyClaimsForRequest {
	client.generateStackRecord()
	claims := MyClaimsForRequest{
		client.currentInfo["appid"],
		client.currentInfo["appkey"],
		client.currentInfo["channel"],
		client.targetInfo["appid"],
		client.targetInfo["appkey"],
		client.targetInfo["channel"],
		client.targetInfo["alias"],
		client.accountId,
		client.subOrgKey,
		client.baseAccountInfo,
		client.generateStackRecord(),
		jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + 60,
			Issuer:    "ItfarmGoSdk",
			IssuedAt:  time.Now().Unix(),
			NotBefore: time.Now().Unix(),
		},
	}
	return claims
}

func (client oldClient) generateStackRecord() []map[string]string {
	tempStack := client.callStacks
	tempStack = append(tempStack, client.targetInfo)
	return tempStack
}

func (client *oldClient) makeToken(claims MyClaimsForRequest) {
	client.token = client.MakeToken(claims, 60)
}

func (client oldClient) MakeToken(claims MyClaimsForRequest, expire int64) string {
	claims.ExpiresAt = time.Now().Unix() + expire
	token := jwt.NewWithClaims(getSigner(), claims)
	result, _ := token.SignedString([]byte(client.getAppSecret()))
	return result
}

func (client oldClient) getAppSecret() string {
	return client.appSecret
}

func (client *oldClient) Exec(serviceName string,
	method string,
	api string,
	data map[string]interface{},
	contentType string,
	file *fileStruct) ([]byte, error) {
	method = strings.ToUpper(method)
	url1, err := client.checkParam(serviceName, method, data)
	if err != nil {
		return nil, err
	}
	api = strings.TrimLeft(api, " \t\n\r/")
	tr := &http.Transport{TLSHandshakeTimeout: client.connectTimeout,
		ResponseHeaderTimeout: client.timeout}
	theoldClient := &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	var request *http.Request
	var err1 error
	switch contentType {
	case CONTENT_TYPE_FORM:
		theData := url.Values{}
		for k, v := range data {
			theData.Set(k, fmt.Sprint(v))
		}
		request, err1 = http.NewRequest(method, url1+api, strings.NewReader(theData.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case CONTENT_TYPE_JSON:
		theData := make(map[string]interface{})
		for k, v := range data {
			theData[k] = v
		}
		bytesData, err := json.Marshal(theData)
		if err != nil {
			return nil, errno.JSON_ERROR.Add(err.Error())
		}
		request, err1 = http.NewRequest(method, url1+api, bytes.NewReader(bytesData))
		request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	case CONTENT_TYPE_MULTIPART:
		buff := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(buff)

		// 写入文件
		fileWriter, err := bodyWriter.CreateFormFile(file.fileKey, file.fileName)
		if err != nil {
			return nil, errno.SDK_ERROR.Add(err.Error())
		}

		_, err2 := io.Copy(fileWriter, file.file)
		if err2 != nil {
			return nil, errno.SDK_ERROR.Add(err2.Error())
		}

		// 写入其他参数
		for k, v := range data {
			err := bodyWriter.WriteField(k, fmt.Sprint(v))
			if err != nil {
				return nil, errno.DATA_WRONG_TYPE.Add("data type wrong")
			}
		}

		defer bodyWriter.Close()

		request, err1 = http.NewRequest(method, url1+api, buff)
		request.Header.Set("Content-Type", bodyWriter.FormDataContentType())
	default:
		return nil, errno.CONTENT_TYPE_ERROR.Add("content_type should be " + CONTENT_TYPE_FORM + " or " + CONTENT_TYPE_JSON + " or " + CONTENT_TYPE_MULTIPART)
	}
	if err1 != nil {
		return nil, errno.NETWORK_CONNECT_ERROR.Add("new request failed")
	}

	if client.token != "" {
		request.Header.Set("Authorization", "Bearer "+client.token)
	}
	request.Header.Set("Accept", "application/json")

	if client.header.Get("HTTP_X_FORWARDED_FOR") != "" {
		for _, v := range client.header["HTTP_X_FORWARDED_FOR"] {
			request.Header.Add("X-FORWARDED-FOR", v)
		}

	}
	if client.header.Get("HTTP_X_FORWARDED_PROTO") != "" {
		for _, v := range client.header["HTTP_X_FORWARDED_PROTO"] {
			request.Header.Add("X-FORWARDED-PROTO", v)
		}

	}
	if client.header.Get("HTTP_FRONT_END_HTTPS") != "" {
		for _, v := range client.header["HTTP_FRONT_END_HTTPS"] {
			request.Header.Add("FRONT-END-HTTPS", v)
		}

	}
	request.Header.Set("User-Agent", USER_AGENT+"/"+VERSION)
	if client.header.Get("HTTP_USER_AGENT") != "" {
		for _, v := range client.header["HTTP_USER_AGENT"] {
			request.Header.Add("User-Agent", v)
		}
	}

	response, err2 := theoldClient.Do(request)
	if err2 != nil {
		return nil, errno.NETWORK_CONNECT_ERROR.Add("connect failed:" + err2.Error())
	}
	defer response.Body.Close()
	if response.StatusCode == 200 {
		return parseResponse(response)
	} else {
		return nil, requestError(response)
	}

}

func (client *oldClient) checkParam(serviceName string,
	method string,
	data map[string]interface{}) (string, error) {
	baseUrl, err := client.getServiceUrl(serviceName)
	if err != nil {
		return "", err
	}
	method = strings.ToUpper(method)
	allowMethods := []string{"POST", "GET", "PUT"}
	var flag = false
	for _, v := range allowMethods {
		if v == method {
			flag = true
		}
	}
	if !flag {
		return "", errno.METHOD_NOT_ALLOWED.Add("method not allowed")
	}
	//phpsdk这里还要判断data是否是数组类型，go中就不判断了
	return baseUrl, nil
}

var configServices map[string]string

//获取服务的路径
func (client *oldClient) getServiceUrl(serviceName string) (string, error) {
	//	不是在中台部署的项目可以将项目名和地址存入client.services[]中，已经调用过的服务也会存在该数组中，不用重新查询
	if client.services[serviceName] != "" {
		return client.services[serviceName], nil
	}
	//	网关+服务名，暂时没用，该网关也是从环境变量中取得，在client初始化时取得，也是中台设置的
	if client.proxy != "" {
		client.services[serviceName] = client.proxy + "/" + serviceName + "/"
		return client.services[serviceName], nil
	}

	//	在中台部署的项目会帮你在开发空间设置环境变量
	serviceUrl := os.Getenv("DEPLOYMENT_" + serviceName + "_HOST")
	if serviceUrl != "" {
		serviceUrl = strings.TrimRight(serviceUrl, "/") + "/"
		client.services[serviceName] = serviceUrl
		return client.services[serviceName], nil
	} else {
		serviceUrl = os.Getenv("WORKSPACE_" + serviceName + "_HOST")
		if serviceUrl != "" {
			serviceUrl = strings.TrimRight(serviceUrl, "/") + "/"
			client.services[serviceName] = serviceUrl
			return client.services[serviceName], nil
		}
	}

	if configServices == nil {
		servicesString := os.Getenv("services")
		if servicesString != "" {
			configServices = make(map[string]string)
			data, err := base64.StdEncoding.DecodeString(servicesString)
			if err != nil {
				return "", errno.SERVICE_TYPE_ERROR.Add("services should be json format")
			}
			err = json.Unmarshal(data, &configServices)
			if err != nil {
				return "", errno.SERVICE_TYPE_ERROR.Add("services should be json format")
			}
			for k, v := range configServices {
				client.services[k] = strings.TrimRight(v, "/") + "/"
			}
			if client.services[serviceName] == "" {
				return "", errno.SERVICE_NOT_FOUND.Add("service not set")
			}
			return client.services[serviceName], nil
		}
	}
	return "", errno.SERVICE_NOT_FOUND.Add("Can not find url of service:" + serviceName)
}

func parseResponse(response *http.Response) ([]byte, error) {
	body := response.Body
	result, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, errno.RESPONSE_CONTENT_TYPE_ERROR.Add("invalid json format")
	}
	return result, nil
}

func (client *oldClient) CallAsApp(serviceName string,
	method string,
	api string,
	data map[string]interface{},
	contentType string,
	multiPart *fileStruct) ([]byte, error) {
	return client.Exec(serviceName, method, api, data, contentType, multiPart)
}

func (client *oldClient) CallByChain(chains []map[string]string,
	method string,
	api string,
	data map[string]interface{},
	contentType string,
	files *fileStruct) ([]byte, error) {
	if !client.inited {
		return nil, errno.SDK_NOT_INITED.Add("The sdk is not full inited to process the request")
	}
	if client.proxy == "" {
		return nil, errno.GATEWAY_MISSING.Add("Can not find the gateway url, so can not process the request")
	}
	if chains[0]["appid"] != client.currentInfo["appid"] || chains[0]["appkey"] != client.currentInfo["appkey"] || chains[0]["channel"] != client.currentInfo["channel"] {
		return nil, errno.CHAIN_INVALID.Add("The chain does not match the caller info")
	}
	var isChainValid = true
	var stack = make(map[string]string)
	for _, chain := range chains {
		if chain["appid"] == "" {
			isChainValid = false
			break
		}
		if chain["channelAlias"] == "" {
			if chain["appkey"] == "" {
				isChainValid = false
				break
			}
		}
		stack = generateStackRow(chain["appid"], chain["appkey"], chain["channel"], chain["channelAlias"], "")
	}
	if !isChainValid {
		return nil, errno.CHAIN_INVALID.Add("Invalid chains input")
	}
	if client.services["gateway_chain"] == "" {
		client.services["gateway_chain"] = client.proxy + "/chain/"
	}
	claims := client.claimsForChainRequest(stack)
	client.makeTokenByChain(claims)
	return client.Exec("gateway_chain", method, api, data, contentType, files)
}

func (client *oldClient) claimsForChainRequest(stack map[string]string) MyClaimsForChainRequest {
	claims := MyClaimsForChainRequest{
		client.accountId,
		client.subOrgKey,
		client.baseAccountInfo,
		append(client.callStacks, stack),
		jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + 60,
			Issuer:    "ItfarmGoSdk",
			IssuedAt:  time.Now().Unix(),
			NotBefore: time.Now().Unix(),
		},
	}
	return claims
}

func (client *oldClient) makeTokenByChain(claims MyClaimsForChainRequest) {
	client.token = client.MakeTokenByChain(claims)
}

func (client oldClient) MakeTokenByChain(claims MyClaimsForChainRequest) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	result, _ := token.SignedString([]byte(""))
	return result
}

func (client *oldClient) CallServiceInstance(appid string,
	appkey string,
	channel string,
	method string,
	api string,
	param map[string]interface{},
	contentType string,
	files *fileStruct) ([]byte, error) {
	if appid == "" || appkey == "" || channel == "" {
		return nil, errno.INVALID_PARAM.Add("Appid ,appkey can not be null or empty string ,channel can not be null")
	}
	if !client.inited {
		return nil, errno.SDK_NOT_INITED.Add("The sdk is not full inited , can not process this request")
	}
	client.targetInfo = generateStackRow(appid, appkey, channel, "", "")
	claims := client.claimsForThisRequest()
	client.makeToken(claims)
	return client.Exec(appid, method, api, param, contentType, files)
}

func (client *oldClient) GetCurrentToken(appid, appkey, channel, alias string) string {
	client.targetInfo = generateStackRow(appid, appkey, channel, alias, "")
	claims := client.claimsForThisRequest()
	client.makeToken(claims)
	return client.token
}

func (client *oldClient) UploadFile(serviceName string,
	api string,
	files *fileStruct,
	data map[string]interface{},
	channelAlias string) ([]byte, error) {
	claims := client.claimsForThisRequest()
	if client.isTokenIssuer {
		client.makeToken(claims)
	}
	return client.Call(serviceName, "POST", api, data, channelAlias, CONTENT_TYPE_MULTIPART, files)
}
