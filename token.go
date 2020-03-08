package gosdk

import (
	"net/http"
	"strings"
)

func GetBearerToken(header http.Header) string {
	headers := getAuthorizationHeader(header)
	// HEADER: Get the access token from the header
	authScheme := "Bearer"
	l := len(authScheme)
	tokenString := ""
	if len(headers) > l+1 && headers[:l] == authScheme {
		tokenString = headers[l+1:]
	}
	return tokenString
}

func getAuthorizationHeader(header http.Header) (headers string) {
	//var headers string
	if header.Get("Authorization") != "" {
		headers = strings.Trim(header.Get("Authorization"), " \t\n\r")
	} else if header.Get("HTTP_AUTHORIZATION") != "" {
		headers = strings.Trim(header.Get("HTTP_AUTHORIZATION"), " \t\n\r")
	}

	return headers
}

/*func GetAppInfoByToken(tokenString string) (map[string]interface{}, *CommError) {
	if tokenString == "" {
		return nil,&CommError{204,"token is empty"}
	}
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (i interface{}, e error) {
		return token, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		tokenData = make(map[string]interface{})
		for key, value := range claims {
			tokenData[key] = value
		}
		return tokenData,nil
	}
	return nil,&CommError{204,"token format claim error"}
}*/
