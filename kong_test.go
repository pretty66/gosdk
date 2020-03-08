package gosdk

import (
	"fmt"
	"github.com/pretty66/gosdk/cienv"
	"testing"
)

var testClient Client

func init() {
	// 代码中添加kong代理地址，手动指定使用kong网关
	err = cienv.SetEnv(GATEWAY_SERVICE_KEY, "kong:http://127.0.0.1:13800")
	if err != nil {
		panic(err)
	}
	testClient, err = GetClientInstance(nil)
	// 应用则指定自身
	err = testClient.SetAppInfo("app", "4c2561d1fee443b88b6a9acdbfa0eb36", "2", "")
	if err != nil {
		panic(err)
	}
}

func TestKongClient_Call(t *testing.T) {

	res ,err := testClient.Call("call_service", "get", "/", map[string]interface{}{"asd":"qwe"}, "test", CONTENT_TYPE_FORM, nil)
	if err != nil {
		fmt.Printf("%#v", err)
		return
	}
	fmt.Println(string(res))
}


func TestClient_CallByChain(t *testing.T) {
	chains := []map[string]string{}
	chains = append(chains, map[string]string{
		"appid":"app",
		"appkey":"4c2561d1fee443b88b6a9acdbfa0eb36",
		"channel":"2",
	}, map[string]string{
		"appid":"server1",
		"alias":"test",
	} , map[string]string{
		"appid":"server3",
		"alias":"test",
	})
	res, err := testClient.CallByChain(chains, "get", "/server3", nil, CONTENT_TYPE_FORM, nil)
	if err != nil {
		fmt.Printf("%#v", err)
		return
	}
	fmt.Println(string(res))
}

func TestClient_CallByChain2(t *testing.T) {
	chains := []map[string]string{}
	chains = append(chains, map[string]string{
		"appid":"app",
		"appkey":"4c2561d1fee443b88b6a9acdbfa0eb36",
		"channel":"2",
	}, map[string]string{
		"appid":"server1",
		"alias":"test",
	} , map[string]string{
		"appid":"call_service",
		"appkey":"d21623f9b2b5401daacca65824dc8677",
		"channel":"2",
		"alias":"-",
	})
	res, err := testClient.CallByChain(chains, "get", "/", nil, CONTENT_TYPE_FORM, nil)
	if err != nil {
		fmt.Printf("%#v", err)
		return
	}
	fmt.Println(string(res))
}


func TestKongClient_CallServiceInstance(t *testing.T) {
	res ,err := testClient.CallServiceInstance("call_service", "d21623f9b2b5401daacca65824dc8677", "2", "get", "/", map[string]interface{}{"asd":"qwe"}, CONTENT_TYPE_FORM, nil)
	if err != nil {
		fmt.Printf("%#v", err)
		return
	}
	fmt.Println(string(res))
}


func TestKongClient_UploadFile(t *testing.T) {
	res ,err := testClient.UploadFile("server1", "/call", nil, nil, "test")
	if err != nil {
		fmt.Printf("%#v", err)
		return
	}
	fmt.Println(string(res))
}