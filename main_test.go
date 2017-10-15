package main

import (
	"github.com/coderanger/kubernetes-github-authn/mocks"

	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-github/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	authentication "k8s.io/client-go/pkg/apis/authentication/v1beta1"
)

const OrgToken = "072bf484f3a776730d1fb0a4c27718a25a45db13"
const NotOrgToken = "e7aa087b9c1a0d102f4f10f1e0201dbb94753f26"

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
	mockClient.On("UserGet", "").Return(nil, nil, errors.New("boom"))
	ui := &authentication.UserInfo{}
	err := checkUser(mockClient, ui)
	assert.NotNil(t, err)
	assert.Equal(t, ui.Username, "")
	assert.Equal(t, ui.UID, "")
}

func TestCheckOrgs(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockName := "orgone"
	mockMemberships := []*github.Membership{
		&github.Membership{Organization: &github.Organization{Login: &mockName}},
	}
	mockClient.On("ListOrgMemberships", mock.MatchedBy(func(opt *github.ListOrgMembershipsOptions) bool {
		return opt.Page == 0
	})).Return(mockMemberships, &github.Response{Response: &http.Response{StatusCode: 200}, NextPage: 0}, nil)
	ui := &authentication.UserInfo{}
	err := checkOrgs(mockClient, ui)
	assert.Nil(t, err)
	assert.Equal(t, ui.Groups, []string{"github:orgone"})
}

func TestBlankCheckOrgs(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockMemberships := []*github.Membership{}
	mockClient.On("ListOrgMemberships", mock.MatchedBy(func(opt *github.ListOrgMembershipsOptions) bool {
		return opt.Page == 0
	})).Return(mockMemberships, &github.Response{Response: &http.Response{StatusCode: 200}, NextPage: 0}, nil)
	ui := &authentication.UserInfo{}
	err := checkOrgs(mockClient, ui)
	assert.Nil(t, err)
	assert.Nil(t, ui.Groups)
}

func TestBadCheckOrgs(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockMemberships := []*github.Membership{}
	mockClient.On("ListOrgMemberships", mock.MatchedBy(func(opt *github.ListOrgMembershipsOptions) bool {
		return opt.Page == 0
	})).Return(mockMemberships, &github.Response{Response: &http.Response{StatusCode: 500}, NextPage: 0}, errors.New("boom"))
	ui := &authentication.UserInfo{}
	err := checkOrgs(mockClient, ui)
	assert.NotNil(t, err)
	assert.Nil(t, ui.Groups)
}

func TestUnauthCheckOrgs(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockMemberships := []*github.Membership{}
	mockClient.On("ListOrgMemberships", mock.MatchedBy(func(opt *github.ListOrgMembershipsOptions) bool {
		return opt.Page == 0
	})).Return(mockMemberships, &github.Response{Response: &http.Response{StatusCode: 403}, NextPage: 0}, errors.New("boom"))
	ui := &authentication.UserInfo{}
	err := checkOrgs(mockClient, ui)
	assert.Nil(t, err)
	assert.Nil(t, ui.Groups)
}

func TestMulitCheckOrgs(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockName := "orgone"
	mockName2 := "orgtwo"
	mockMemberships := []*github.Membership{
		&github.Membership{Organization: &github.Organization{Login: &mockName}},
		&github.Membership{Organization: &github.Organization{Login: &mockName2}},
	}
	mockClient.On("ListOrgMemberships", mock.MatchedBy(func(opt *github.ListOrgMembershipsOptions) bool {
		return opt.Page == 0
	})).Return(mockMemberships, &github.Response{Response: &http.Response{StatusCode: 200}, NextPage: 0}, nil)
	ui := &authentication.UserInfo{}
	err := checkOrgs(mockClient, ui)
	assert.Nil(t, err)
	assert.Equal(t, ui.Groups, []string{"github:orgone", "github:orgtwo"})
}

func TestPagedCheckOrgs(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockName := "orgone"
	mockName2 := "orgtwo"
	mockMemberships := []*github.Membership{
		&github.Membership{Organization: &github.Organization{Login: &mockName}},
	}
	mockMemberships2 := []*github.Membership{
		&github.Membership{Organization: &github.Organization{Login: &mockName2}},
	}
	mockClient.On("ListOrgMemberships", mock.MatchedBy(func(opt *github.ListOrgMembershipsOptions) bool {
		return opt.Page == 0
	})).Return(mockMemberships, &github.Response{Response: &http.Response{StatusCode: 200}, NextPage: 1}, nil)
	mockClient.On("ListOrgMemberships", mock.MatchedBy(func(opt *github.ListOrgMembershipsOptions) bool {
		return opt.Page == 1
	})).Return(mockMemberships2, &github.Response{Response: &http.Response{StatusCode: 200}, NextPage: 0}, nil)
	ui := &authentication.UserInfo{}
	err := checkOrgs(mockClient, ui)
	assert.Nil(t, err)
	assert.Equal(t, ui.Groups, []string{"github:orgone", "github:orgtwo"})
}

func TestCheckTeams(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockName := "orgone"
	mockTeam := "teamone"
	mockTeams := []*github.Team{
		&github.Team{Organization: &github.Organization{Login: &mockName}, Slug: &mockTeam},
	}
	mockClient.On("ListUserTeams", mock.MatchedBy(func(opt *github.ListOptions) bool {
		return opt.Page == 0
	})).Return(mockTeams, &github.Response{Response: &http.Response{StatusCode: 200}, NextPage: 0}, nil)
	ui := &authentication.UserInfo{}
	err := checkTeams(mockClient, ui)
	assert.Nil(t, err)
	assert.Equal(t, ui.Groups, []string{"github:orgone:teamone"})
}

func TestBlankCheckTeams(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockTeams := []*github.Team{}
	mockClient.On("ListUserTeams", mock.MatchedBy(func(opt *github.ListOptions) bool {
		return opt.Page == 0
	})).Return(mockTeams, &github.Response{Response: &http.Response{StatusCode: 200}, NextPage: 0}, nil)
	ui := &authentication.UserInfo{}
	err := checkTeams(mockClient, ui)
	assert.Nil(t, err)
	assert.Nil(t, ui.Groups)
}

func TestBadCheckTeams(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockTeams := []*github.Team{}
	mockClient.On("ListUserTeams", mock.MatchedBy(func(opt *github.ListOptions) bool {
		return opt.Page == 0
	})).Return(mockTeams, &github.Response{Response: &http.Response{StatusCode: 500}, NextPage: 0}, errors.New("boom"))
	ui := &authentication.UserInfo{}
	err := checkTeams(mockClient, ui)
	assert.NotNil(t, err)
	assert.Nil(t, ui.Groups)
}

func TestUnauthCheckTeams(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockTeams := []*github.Team{}
	mockClient.On("ListUserTeams", mock.MatchedBy(func(opt *github.ListOptions) bool {
		return opt.Page == 0
	})).Return(mockTeams, &github.Response{Response: &http.Response{StatusCode: 404}, NextPage: 0}, errors.New("boom"))
	ui := &authentication.UserInfo{}
	err := checkTeams(mockClient, ui)
	assert.Nil(t, err)
	assert.Nil(t, ui.Groups)
}

func TestMulitCheckTeams(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockName := "orgone"
	mockTeam := "teamone"
	mockName2 := "orgtwo"
	mockTeam2 := "teamtwo"
	mockTeams := []*github.Team{
		&github.Team{Organization: &github.Organization{Login: &mockName}, Slug: &mockTeam},
		&github.Team{Organization: &github.Organization{Login: &mockName}, Slug: &mockTeam2},
		&github.Team{Organization: &github.Organization{Login: &mockName2}, Slug: &mockTeam2},
	}
	mockClient.On("ListUserTeams", mock.MatchedBy(func(opt *github.ListOptions) bool {
		return opt.Page == 0
	})).Return(mockTeams, &github.Response{Response: &http.Response{StatusCode: 200}, NextPage: 0}, nil)
	ui := &authentication.UserInfo{}
	err := checkTeams(mockClient, ui)
	assert.Nil(t, err)
	assert.Equal(t, ui.Groups, []string{"github:orgone:teamone", "github:orgone:teamtwo", "github:orgtwo:teamtwo"})
}

func TestPagedCheckTeams(t *testing.T) {
	mockClient := &mocks.GithubService{}
	mockName := "orgone"
	mockTeam := "teamone"
	mockName2 := "orgtwo"
	mockTeam2 := "teamtwo"
	mockTeams := []*github.Team{
		&github.Team{Organization: &github.Organization{Login: &mockName}, Slug: &mockTeam},
	}
	mockTeams2 := []*github.Team{
		&github.Team{Organization: &github.Organization{Login: &mockName2}, Slug: &mockTeam2},
	}
	mockClient.On("ListUserTeams", mock.MatchedBy(func(opt *github.ListOptions) bool {
		return opt.Page == 0
	})).Return(mockTeams, &github.Response{Response: &http.Response{StatusCode: 200}, NextPage: 1}, nil)
	mockClient.On("ListUserTeams", mock.MatchedBy(func(opt *github.ListOptions) bool {
		return opt.Page == 1
	})).Return(mockTeams2, &github.Response{Response: &http.Response{StatusCode: 200}, NextPage: 0}, nil)
	ui := &authentication.UserInfo{}
	err := checkTeams(mockClient, ui)
	assert.Nil(t, err)
	assert.Equal(t, ui.Groups, []string{"github:orgone:teamone", "github:orgtwo:teamtwo"})
}

func TestAuthenticate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping internet-required tests due to -short")
	}
	json := `{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "TokenReview",
  "spec": {
    "token": "` + OrgToken + `"
  }
}`
	req := httptest.NewRequest("POST", "http://hook/authenticate", strings.NewReader(json))
	ui, err := authenticate(req)
	assert.Nil(t, err)
	assert.Equal(t, ui.Username, "kubernetes-github-authn-test")
	assert.Equal(t, ui.UID, "32822820")
	assert.Equal(t, ui.Groups, []string{"github:kubernetes-github-authn-testorg", "github:kubernetes-github-authn-testorg:admins"})
}

func TestNoOrgAuthenticate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping internet-required tests due to -short")
	}
	json := `{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "TokenReview",
  "spec": {
    "token": "` + NotOrgToken + `"
  }
}`
	req := httptest.NewRequest("POST", "http://hook/authenticate", strings.NewReader(json))
	ui, err := authenticate(req)
	assert.Nil(t, err)
	assert.Equal(t, ui.Username, "kubernetes-github-authn-test")
	assert.Equal(t, ui.UID, "32822820")
	assert.Nil(t, ui.Groups)
}
