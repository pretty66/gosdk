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
	firstChain map[string]string
	lastChain  map[string]string
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
		callStack := server.GetCallStack()
		if len(callStack) > 0 {
			server.firstChain = callStack[0]
			server.lastChain = callStack[len(callStack)-1]
		} else {
			server.firstChain = map[string]string{}
			server.lastChain = map[string]string{}
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
		if ok && appid != "" {
			return appid
		}
		appid, _ = server.lastChain[TO_APPID_KEY]
	}
	return appid
}

func (server *Server) GetAppKey() string {
	appkey := server.header.Get(SELF_APPKEY_KEY)
	if appkey != "" {
		return appkey
	}
	if server.token != nil {
		appkey, ok := server.token.Claims.(jwt.MapClaims)[TO_APPKEY_KEY].(string)
		if ok && appkey != "" {
			return appkey
		}
		appkey, _ = server.lastChain[TO_APPKEY_KEY]
	}
	return appkey
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
		channel, _ = server.lastChain[TO_CHANNEL]
	}
	return ""
}

func (server *Server) GetAccountId() string {
	if server.token != nil {
		accountId, ok := server.token.Claims.(jwt.MapClaims)[ACCOUNT_ID_KEY].(string)
		if ok {
			return accountId
		}
	}
	return ""
}

func (server *Server) GetSubOrgKey() string {
	if server.token != nil {
		subOrgKey, ok := server.token.Claims.(jwt.MapClaims)[SUB_ORG_KEY_KEY].(string)
		if ok {
			return subOrgKey
		}
	}
	return ""
}

func (server *Server) GetUserInfo() map[string]string {
	if server.token != nil {
		userInfo, ok := server.token.Claims.(jwt.MapClaims)[USER_INFO_KEY].(map[string]string)
		if ok {
			return userInfo
		}
	}
	return map[string]string{}
}

func (server *Server) GetFromAppKey() string {
	if server.token != nil {
		fromAppkey, ok := server.token.Claims.(jwt.MapClaims)[FROM_APPKEY_KEY].(string)
		if ok {
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
		fromAppid, ok := server.token.Claims.(jwt.MapClaims)[FROM_APPID_KEY].(string)
		if ok {
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
		var res []map[string]interface{}
		err = json.Unmarshal(b, &res)
		if err != nil {
			return []map[string]string{}
		}
		out := make([]map[string]string, len(res))
		for index, chain := range res {
			tmp := map[string]string{}
			for key, val := range chain {
				tmp[key] = GetInterfaceString(val)
			}
			out[index] = tmp
		}
		return out
	}
	return []map[string]string{}
}

func (s *Server) GetToken() string {
	return s.token.Raw
}

func (s *Server) GetFirstChain() map[string]string {
	return s.firstChain
}

func (s *Server) GetLastChain() map[string]string {
	return s.lastChain
}

func (s *Server) IsCallByAdmin() bool {
	if s.tokenExist {
		super, _ := s.token.Claims.(jwt.MapClaims)[SUPER_ACCOUNT_ID_KEY].(string)
		return super == SUPER_ADMIN_ACCOUNT_ID
	}
	return false
}

func (s *Server) GetSuperAdmin() string {
	super, _ := s.token.Claims.(jwt.MapClaims)[SUPER_ACCOUNT_ID_KEY].(string)
	return super
}

func (s *Server) GetHeader(key string) string {
	return s.header.Get(key)
}
