package gosdk

import "encoding/json"

func MakeService(appId, appKey, channel string) string {
	return NewMd5(appId, appKey, channel)
}

func MakeRoute(fromAppKey, fromChannel, toAppId, toChannelAlias string) string {
	return NewMd5(fromAppKey, fromChannel, toAppId, toChannelAlias)
}

func MakeInstanceRoute(fromAppId, fromAppKey, fromChannel, toAppId, toAppKey, toChannel string) string {
	return NewImplodeMd5(",", fromAppId, fromAppKey, fromChannel, toAppId, toAppKey, toChannel)
}

func MakeConsumer(fromAppId, fromAppKey, fromChannel string) string {
	return NewMd5(fromAppId, fromAppKey, fromChannel)
}

func MakeSecret(fromAppId, fromAppKey, fromChannel string) string {
	return NewImplodeMd5("__", fromAppId, fromAppKey, fromChannel)
}

func MakeChains(chains []map[string]string) string {
	b, _ := json.Marshal(chains)
	return NewMd5(string(b))
}





