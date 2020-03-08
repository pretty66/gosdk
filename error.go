package gosdk

type CommError struct {
	Code int
	Msg  string
}

func (e *CommError) Error() string {
	return e.Msg
}

const (
	METHOD_NOT_ALLOWED = 1001
	DATA_WRONG_TYPE    = 1002
	CONTENT_TYPE_ERROR = 1003
	FILE_TYPE_ERROR    = 1004
	/**
	 * from 1101 to 1199 network and request and response error
	 */
	NETWORK_CONNECT_ERROR       = 1101
	RESPONSE_CONTENT_TYPE_ERROR = 1111
	RESPONSE_404                = 1120
	RESPONSE_401                = 1121
	RESPONSE_403                = 1122
	RESPONSE_OTHER              = 1123
	UNKNOWN_ERROR               = 1130
	NETWORK_EMPTY_RESPONSE      = 1102

	/**
	 * from 1301 to 1399 sdk inner error
	 */
	TOKEN_INVALID            = 1201
	SERVICE_TYPE_ERROR       = 1202
	SERVICE_NOT_FOUND        = 1203
	SDK_NOT_INITED           = 1204
	GATEWAY_MISSING          = 1205
	INVALID_PARAM            = 1206
	CAN_NOT_CALL_THIS_METHOD = 1207
)
