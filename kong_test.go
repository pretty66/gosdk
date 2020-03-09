package gosdk

import (
	"fmt"
	"github.com/pretty66/gosdk/cienv"
	"net/http"
	"testing"
)

var testClient Client
var _header http.Header

func init() {
	// 代码中添加kong代理地址，手动指定使用kong网关
	err = cienv.SetEnv(GATEWAY_SERVICE_KEY, "kong:http://127.0.0.1:13800")
	if err != nil {
		panic(err)
	}
	testClient, err = GetClientInstance(_header)
	// 应用则指定自身
	err = testClient.SetAppInfo("app", "4c2561d1fee443b88b6a9acdbfa0eb36", "2", "")
	if err != nil {
		panic(err)
	}
}

func TestKongClient_Call(t *testing.T) {

	res ,err := testClient.Call("server1", "get", "/upload.php", map[string]interface{}{"asd":"qwe"}, "test", CONTENT_TYPE_FORM, nil)
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


func TestGetServerInstance(t *testing.T) {
	server, err := GetServerInstance(_header)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(server.GetAppId())
	fmt.Println(server.GetAppKey())
	fmt.Println(server.GetAccountId())
	fmt.Println(server.GetCallStack())
	fmt.Println(server.GetFromAppId())
	fmt.Println(server.GetFromAppKey())
	fmt.Println(server.GetFromChannel())
}

func TestGetAppInfoByToken(t *testing.T) {
	token := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJJdGZhcm1QaHBTZGsiLCJpYXQiOjE1NjI5MTYyMzUsIm5iZiI6MTU2MjkxNjIzNSwiZXhwIjoxNTYyOTE2Mjk1LCJhY2NvdW50X2lkIjoiMDMxNzYyOGYwMTYwNDE2NmI1NWFlOGQ3OGVjNmRkNjAiLCJhcHBrZXkiOiI0YzI1NjFkMWZlZTQ0M2I4OGI2YTlhY2RiZmEwZWIzNiIsImFwcGlkIjoiYXBwIiwiY2hhbm5lbCI6IjIiLCJzdWJfb3JnX2tleSI6IjAiLCJ1c2VyX2luZm8iOltdLCJjYWxsX3N0YWNrIjpbXX0.s_2uYmOzVZGP6cHKMJbIN-85TljPLPIU7vNhGQXK21g`
	res, err := GetAppInfoByToken(token)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(res)
}