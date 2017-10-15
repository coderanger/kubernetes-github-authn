package main

import (
	"context"
	"net/url"
	"os"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

type GithubService interface {
	UserGet(string) (*github.User, *github.Response, error)
	ListOrgMemberships(*github.ListOrgMembershipsOptions) ([]*github.Membership, *github.Response, error)
	ListUserTeams(*github.ListOptions) ([]*github.Team, *github.Response, error)
}

type goGithubService struct {
	client *github.Client
}

func (s *goGithubService) UserGet(name string) (*github.User, *github.Response, error) {
	return s.client.Users.Get(context.Background(), name)
}

func (s *goGithubService) ListOrgMemberships(opts *github.ListOrgMembershipsOptions) ([]*github.Membership, *github.Response, error) {
	return s.client.Organizations.ListOrgMemberships(context.Background(), opts)
}

func (s *goGithubService) ListUserTeams(opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
	return s.client.Organizations.ListUserTeams(context.Background(), opts)
}

func newGithubClient(ts oauth2.TokenSource) (GithubService, error) {
	tc := oauth2.NewClient(oauth2.NoContext, ts)
	client := github.NewClient(tc)
	if baseurl, ok := os.LookupEnv("GITHUB_BASEURL"); ok {
		var err error
		client.BaseURL, err = url.Parse(baseurl)
		if err != nil {
			return nil, err
		}
	}
	return &goGithubService{client: client}, nil
}
