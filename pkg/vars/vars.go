package vars

var CliCommand string

var ClientId string

var ProdBaseUrl string = "NOT_SET_DURING_BUILD"

var DevBaseUrl string = "NOT_SET_DURING_BUILD"

var UrlMap = map[string]string{
	"prod": ProdBaseUrl,
	"dev": DevBaseUrl,
}

var AuthorizationEndpoint string = "/oauth/device-authorization/"

var TokenEndpoint string = "/oauth/token/"

