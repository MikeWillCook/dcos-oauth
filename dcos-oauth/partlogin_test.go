package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/context"

	"github.com/stretchr/testify/assert"
	"strings"
)

func TestHandlePartLogin(t *testing.T) {
	aAssert := assert.New(t)
	ctx := context.Background()
	unusedUrl := "URL not used in testing"
	var respBody []byte
	var testCase string

	r, _ := http.NewRequest("GET", unusedUrl, nil)
	w := httptest.NewRecorder()
	ctx = context.WithValue(ctx, "issuer-url", "https://dcos.auth0.com/")
	ctx = context.WithValue(ctx, "client-id", "3yF5TOSzdlI45Q1xspxzeoGBe9fNxm9m")
	ctx = context.WithValue(ctx, "secret-key", "12345")

	testCase = "Expecting StatusBadRequest error when request body has invalid json"
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("invalid"))
	aAssert.Equal("Bad Request", handlePartLogin(ctx, w, r).Title, testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("", string(respBody), testCase)

	testCase = "Expecting success with valid oauth and no user authorization"
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader(validTokenJson))
	aAssert.Nil(handlePartLogin(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Contains(string(respBody), "\"token\":\"", "Expecting response to contain a new token")
}
