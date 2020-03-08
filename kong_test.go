package gosdk

import (
	"fmt"
	"gosdk/cienv"
	"testing"
)

var testClient Client

func init() {
	err = cienv.SetEnv(GATEWAY_SERVICE_KEY, "kong:http://127.0.0.1:13800")
	if err != nil {
		panic(err)
	}
	testClient, err = GetClientInstance(nil)
	err = testClient.SetAppInfo("app", "4c2561d1fee443b88b6a9acdbfa0eb36", "2", "")
	if err != nil {
		panic(err)
	}
}

func TestKongClient_Call(t *testing.T) {

	res ,err := testClient.Call("server2", "get", "/", map[string]interface{}{"asd":"qwe"}, "test", CONTENT_TYPE_FORM, nil)
	if err != nil {
		fmt.Printf("%#v", err)
		return
	}
	fmt.Println(string(res))
}