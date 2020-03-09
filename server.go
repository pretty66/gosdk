package gosdk


import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/pretty66/gosdk/errno"
	"net/http"
	"strconv"
)

type Server struct {
	header     http.Header
	token      *jwt.Token
	tokenData  map[string]interface{}
	tokenExist bool
}

func GetServerInstance(header http.Header) (Server, error) {
	server := Server{}
	server.header = header
	token := GetBearerToken(header)
	if token != "" {
		server.token, _ = jwt.Parse(token, func(token *jwt.Token) (i interface{}, e error) {
			return token, nil
		})
		if _, ok := server.token.Claims.(jwt.MapClaims); ok {
			server.tokenExist = true
		} else {
			return server, errno.TOKEN_INVALID
		}
	}
	return server, nil
}

func (server *Server) SetToken(token string) error {
	if token != "" {
		server.token, _ = jwt.Parse(token, func(token *jwt.Token) (i interface{}, e error) {
			return token, nil
		})
		if _, ok := server.token.Claims.(jwt.MapClaims); ok {
			server.tokenExist = true
		} else {
			return errno.TOKEN_INVALID
		}
	}
	return nil
}

func (server *Server) GetTokenData() (map[string]interface{}, error) {
	if server.token == nil {
		return nil, errno.TOKEN_INVALID
	}

	server.tokenData = make(map[string]interface{})
	claims, err := server.token.Claims.(jwt.MapClaims)
	if err {
		for key, value := range claims {
			server.tokenData[key] = value
		}
	} else {
		return nil, errno.TOKEN_INVALID
	}

	return server.tokenData, nil
}


func (server *Server) GetAppId() string {
	appid := server.header.Get(SELF_APPID_KEY)
	if appid != "" {
		return appid
	}
	if server.token != nil {
		appid, ok := server.token.Claims.(jwt.MapClaims)[TO_APPID_KEY].(string)
		if ok {
			return appid
		}
	}
	return ""
}

func (server *Server) GetAppKey() string {
	appkey := server.header.Get(SELF_APPKEY_KEY)
	if appkey != "" {
		return appkey
	}
	if server.token != nil {
		appkey, ok := server.token.Claims.(jwt.MapClaims)[TO_APPKEY_KEY].(string)
		if ok {
			return appkey
		}
	}
	return ""
}

func (server *Server) GetChannel() string {
	channel := server.header.Get(SELF_CHANNEL_KEY)
	if channel != "" {
		return channel
	}

	if server.token != nil {
		channel, ok := server.token.Claims.(jwt.MapClaims)[TO_CHANNEL].(string)
		if ok {
			return channel
		}
		channelFloat, ok := server.token.Claims.(jwt.MapClaims)[TO_CHANNEL].(float64)
		if ok {
			channel = strconv.FormatFloat(channelFloat, 'f', 0, 64)
			return channel
		}
	}
	return ""
}

func (server *Server) GetAccountId() string {
	if server.token != nil {
		accountId, err := server.token.Claims.(jwt.MapClaims)[ACCOUNT_ID_KEY].(string)
		if err {
			return accountId
		}
	}
	return ""
}

func (server *Server) GetSubOrgKey() string {
	if server.token != nil {
		subOrgKey, err := server.token.Claims.(jwt.MapClaims)[SUB_ORG_KEY_KEY].(string)
		if err {
			return subOrgKey
		}
	}
	return ""
}

func (server *Server) GetUserInfo() map[string]string {
	if server.token != nil {
		userInfo, err := server.token.Claims.(jwt.MapClaims)[USER_INFO_KEY].(map[string]string)
		if err {
			return userInfo
		}
	}
	return map[string]string{}
}

func (server *Server) GetFromAppKey() string {
	if server.token != nil {
		fromAppkey, err := server.token.Claims.(jwt.MapClaims)[FROM_APPKEY_KEY].(string)
		if err {
			return fromAppkey
		}
	}
	return ""
}

func (server *Server) GetFromChannel() string {
	if server.token != nil {
		fromChannel, ok := server.token.Claims.(jwt.MapClaims)[FROM_CHANNEL_KEY].(string)
		if ok {
			return fromChannel
		}
		channelFloat, ok := server.token.Claims.(jwt.MapClaims)[FROM_CHANNEL_KEY].(float64)
		if ok {
			fromChannel = strconv.FormatFloat(channelFloat, 'f', 0, 64)
			return fromChannel
		}
	}
	return ""
}

func (server *Server) GetFromAppId() string {
	if server.token != nil {
		fromAppid, err := server.token.Claims.(jwt.MapClaims)[FROM_APPID_KEY].(string)
		if err {
			return fromAppid
		}
	}
	return ""
}

func (server *Server) GetCallStack() []map[string]string {
	if server.token != nil {
		callStack, ok := server.token.Claims.(jwt.MapClaims)[CALL_STACK_KEY]
		if !ok {
			return []map[string]string{}
		}
		b, err := json.Marshal(callStack)
		if err != nil {
			return []map[string]string{}
		}
		var out []map[string]string
		err = json.Unmarshal(b, &out)
		if err != nil {
			return []map[string]string{}
		}
		return out
	}
	return []map[string]string{}
}


func (s *Server) GetHeader(key string) string {
	return s.header.Get(key)
}
