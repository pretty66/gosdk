package errno

type Errno struct {
	State int
	Msg   string
}

func (e *Errno) Error() string {
	return e.Msg
}

func (e Errno) Add(s string) *Errno {
	e.Msg += ": " + s
	return &e
}

type ResponseErrno struct {
	State      int
	Msg        string
	HttpCode   int
	OriginBody string
}

func (e *ResponseErrno) Error() string {
	return e.Msg
}

func (e ResponseErrno) SetCode(code int, s string) *ResponseErrno {
	e.HttpCode = code
	e.OriginBody = s
	return &e
}

func (e ResponseErrno) Add(s string) *ResponseErrno {
	e.Msg += ": " + s
	return &e
}

var (
	METHOD_NOT_ALLOWED = &Errno{1001, "method not allowed"}
	DATA_WRONG_TYPE    = &Errno{1002, "data wrong type"}
	CONTENT_TYPE_ERROR = &Errno{1003, "content type error"}
	FILE_TYPE_ERROR    = &Errno{1004, "file type error"}
	SDK_ERROR          = &Errno{1005, "sdk error"}

	/**
	 * from 1101 to 1199 network and request and response error
	 */
	NETWORK_CONNECT_ERROR       = &Errno{1101, "network connect error"}
	REQUEST_HEADER_ERROR        = &Errno{1103, "The request is not valid"}
	RESPONSE_CONTENT_TYPE_ERROR = &Errno{1111, "response content type error"}
	RESPONSE_404                = &ResponseErrno{1120, "api not exist", 404, ""}
	RESPONSE_401                = &ResponseErrno{1121, "Unauthorized", 401, ""}
	RESPONSE_403                = &ResponseErrno{1122, "No permission", 403, ""}
	RESPONSE_OTHER              = &ResponseErrno{1123, "response other", 0, ""}
	UNKNOWN_ERROR               = &Errno{1130, "unknown error"}
	NETWORK_EMPTY_RESPONSE      = &Errno{1102, "network empty response"}

	/**
	 * from 1301 to 1399 sdk inner error
	 */
	TOKEN_INVALID            = &Errno{1201, "token invalid"}
	SERVICE_TYPE_ERROR       = &Errno{1202, "service type error"}
	SERVICE_NOT_FOUND        = &Errno{1203, "service not found"}
	SDK_NOT_INITED           = &Errno{1204, "The skd is not full inited, can not call this method"}
	GATEWAY_MISSING          = &Errno{1205, "gateway missing"}
	INVALID_PARAM            = &Errno{1206, "invalid param"}
	CAN_NOT_CALL_THIS_METHOD = &Errno{1207, "can not call this method"}
	REQUEST_SETING_ERROR     = &Errno{1208, "request seting error"}
	JSON_ERROR               = &Errno{1209, "json error"}
	CHAIN_INVALID            = &Errno{1210, "The chain does not match the caller info"}
)
