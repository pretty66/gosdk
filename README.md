# GO-SDK
## GO-SDK

go语言版本的中台服务调用的SDK

### 下载
* 使用git直接clone到本地的$GOPATH/src下

```bash
mkdir -p $GOPATH/src/gosdk
git clone git@github.com:pretty66/gosdk.git $GOPATH/src/gosdk
## 依赖
- github.com/dgrijalva/jwt-go

```

* 或使用go mod

```bash
# 在go.mod中添加一行
github.com/pretty66/gosdk latest

# 执行go mod vendor
go mod vendor
```
### 依赖
 - github.com/dgrijalva/jwt-go
 
### 基本使用
- sdk内部根据环境变量 GATEWAY_HOST_SERVICE 判断使用走kong网关还是原先网关
- 可手动在代码中指定网关
- 具体使用案参考 [kong_test.go](https://github.com/pretty66/gosdk/blob/master/kong_test.go)
```go
import "github.com/pretty66/gosdk/cienv"
// kong网关
cienv.SetEnv("GATEWAY_HOST_SERVICE", "kong:http://127.0.0.1:13800")
// 老网关
cienv.SetEnv("GATEWAY_HOST_SERVICE", "https://super-gateway.prod1.oneitfarm.com/index.php/")
```
```
// 获取对象，head是请求的HEAD字段，用来解析HEAD中的Authorization中的token
client, err:=gosdk.GetClientInstance(head)

// 对Authorization中的token解析，或对SetToken()中token解析
//一般服务调用时使用token解析
client, err = client.SetToken(token)
// 如果调用方是应用，则通过SetAppInfo进行调用方的信息存储，服务不要使用该方法
client, err = client.SetAppInfo(appid, appkey, channel, version)

// 可以使用SetServices()自定义服务地址，或通过serviceKey从环境变量中寻找服务地址（前者优先级高）
// services是map[string]string，key是serviceKey，value是服务地址
client = client.SetServices(services)

// 调用服务
// serviceKey对应服务地址，就是中台的appid；
// method是请求的方法，如post、get；
// api是具体请求的接口地址；
// params是要传递的参数，是map[string]interface{}的类型；
// alias是服务的别名，自己在中台设置的，一般为"default"；
// contentType是请求的格式，如application/x-www-form-urlencoded;
// file是上传文件时使用，一般为nil。
resp, err1 = client.Call(serviceKey, method, api, params, alias, contentType, file)
```

