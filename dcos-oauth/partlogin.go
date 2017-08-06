package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"

	"github.com/dcos/dcos-oauth/common"
)

func handlePartLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	log.Print("Attempting partial login") //FIXME

	var lr loginRequest
	err := json.NewDecoder(r.Body).Decode(&lr)
	if err != nil {
		log.Printf("Decode: %v", err)
		return common.NewHttpError("JSON decode error", http.StatusBadRequest)
	}
	issuerURL, _ := ctx.Value("issuer-url").(string)
	provCfg, err := oidc.FetchProviderConfig(httpClient, issuerURL)
	if err != nil {
		log.Printf("FetchProviderConfig: %v", err)
		return common.NewHttpError("[OIDC] Fetch provider config error", http.StatusInternalServerError)
	}

	clientID, _ := ctx.Value("client-id").(string)

	cliCfg := oidc.ClientConfig{
		HTTPClient:     httpClient,
		ProviderConfig: provCfg,
		Credentials: oidc.ClientCredentials{
			ID: clientID,
		},
	}
	oidcCli, err := oidc.NewClient(cliCfg)
	if err != nil {
		log.Printf("oidc.NewClient: %v", err)
		return common.NewHttpError("[OIDC] Client creation error", http.StatusInternalServerError)
	}

	token, err := jose.ParseJWT(lr.Token)
	if err != nil {
		log.Printf("ParseJWT: %v", err)
		return common.NewHttpError("JWT parsing failed", http.StatusBadRequest)
	}

	err = oidcCli.VerifyJWT(token)
	if err != nil {
		log.Printf("Ignoring VerifyJWT: %v", err)
		//FIXME return common.NewHttpError("JWT verification failed", http.StatusUnauthorized)
	}

	claims, err := token.Claims()
	if err != nil {
		log.Printf("Claims: %v", err)
		return common.NewHttpError("invalid claims", http.StatusBadRequest)
	}

	// check for Auth0 email verification
	if verified, ok := claims["email_verified"]; ok {
		if b, ok := verified.(bool); ok && !b {
			log.Printf("email not verified")
			return common.NewHttpError("email not verified", http.StatusBadRequest)
		}
	}

	uid, ok, err := claims.StringClaim("email")
	if !ok || err != nil {
		return common.NewHttpError("invalid email claim", http.StatusBadRequest)
	}

	// skip authorization checks on partial login
	log.Printf("Accepted partial login for user %s", uid)
	claims.Add("uid", uid)

	secretKey, _ := ctx.Value("secret-key").([]byte)

	clusterToken, err := jose.NewSignedJWT(claims, jose.NewSignerHMAC("secret", secretKey))
	if err != nil {
		return common.NewHttpError("JWT creation error", http.StatusInternalServerError)
	}
	encodedClusterToken := clusterToken.Encode()

	const cookieMaxAge = 43200 // 12 hours
	// required for IE 6, 7 and 8
	expiresTime := time.Now().Add(cookieMaxAge * time.Second)

	authCookie := &http.Cookie{
		Name:     "dcos-acs-auth-cookie",
		Value:    encodedClusterToken,
		Path:     "/",
		HttpOnly: true,
		Expires:  expiresTime,
		MaxAge:   cookieMaxAge,
	}
	http.SetCookie(w, authCookie)

	user := User{
		Uid:         uid,
		Description: uid,
		IsRemote:    false,
	}
	userBytes, err := json.Marshal(user)
	if err != nil {
		log.Printf("Marshal: %v", err)
		return common.NewHttpError("JSON marshalling failed", http.StatusInternalServerError)
	}
	infoCookie := &http.Cookie{
		Name:    "dcos-acs-info-cookie",
		Value:   base64.URLEncoding.EncodeToString(userBytes),
		Path:    "/",
		Expires: expiresTime,
		MaxAge:  cookieMaxAge,
	}
	http.SetCookie(w, infoCookie)

	json.NewEncoder(w).Encode(loginResponse{Token: encodedClusterToken})

	return nil
}
