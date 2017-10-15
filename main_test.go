package main

import (
	"github.com/coderanger/kubernetes-github-authn/mocks"

	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-github/github"
	"github.com/stretchr/testify/assert"
	authentication "k8s.io/client-go/pkg/apis/authentication/v1beta1"
)

func TestAuthenticationToken(t *testing.T) {
	json := `{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "TokenReview",
  "spec": {
    "token": "mytoken"
  }
}`
	req := httptest.NewRequest("POST", "http://hook/authenticate", strings.NewReader(json))
	ts, err := authenticationToken(req)
	assert.Nil(t, err)
	token, err := ts.Token()
	assert.Nil(t, err)
	assert.Equal(t, token.AccessToken, "mytoken")
}

func TestBadAuthenticationToken(t *testing.T) {
	json := "{"
	req := httptest.NewRequest("POST", "http://hook/authenticate", strings.NewReader(json))
	ts, err := authenticationToken(req)
	assert.NotNil(t, err)
	assert.Nil(t, ts)
}

func TestCheckUser(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockUserLogin := "myuser"
	mockUserID := 123
	mockUser := &github.User{Login: &mockUserLogin, ID: &mockUserID}
	mockClient.On("UserGet", "").Return(mockUser, nil, nil)
	ui := &authentication.UserInfo{}
	err := checkUser(mockClient, ui)
	assert.Nil(t, err)
	assert.Equal(t, ui.Username, "myuser")
	assert.Equal(t, ui.UID, "123")
}

func TestBadCheckUser(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockClient.On("UserGet", "").Return(nil, nil, errors.New("no user found"))
	ui := &authentication.UserInfo{}
	err := checkUser(mockClient, ui)
	assert.NotNil(t, err)
	assert.Equal(t, ui.Username, "")
	assert.Equal(t, ui.UID, "")
}
