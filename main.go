package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	authentication "k8s.io/client-go/pkg/apis/authentication/v1beta1"
)

func authenticationToken(r *http.Request) (oauth2.TokenSource, error) {
	decoder := json.NewDecoder(r.Body)
	var tr authentication.TokenReview
	err := decoder.Decode(&tr)
	if err != nil {
		return nil, err
	}
	return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tr.Spec.Token}), nil
}

func checkUser(client GithubService, ui *authentication.UserInfo) error {
	user, _, err := client.UserGet("")
	if err != nil {
		return err
	}
	ui.Username = user.GetLogin()
	ui.UID = fmt.Sprintf("%d", user.GetID())
	return nil
}

func checkOrgs(client GithubService, ui *authentication.UserInfo) error {
	requiredOrg := os.Getenv("REQUIRED_ORG")
	matchesRequiredOrg := requiredOrg == ""

	opt := &github.ListOrgMembershipsOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	for {
		memberships, resp, err := client.ListOrgMemberships(opt)
		if resp.StatusCode == 403 {
			// Token doesn't have permissions to query memberships.
			return nil
		}
		if err != nil {
			return err
		}
		for _, membership := range memberships {
			ui.Groups = append(ui.Groups, "github:"+membership.Organization.GetLogin())
			if membership.Organization.GetLogin() == requiredOrg {
				matchesRequiredOrg = true
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	if !matchesRequiredOrg {
		return fmt.Errorf("user %s is not a member of require organization %s", ui.Username, requiredOrg)
	}
	return nil
}

func checkTeams(client GithubService, ui *authentication.UserInfo) error {
	opt := &github.ListOptions{PerPage: 100}
	for {
		teams, resp, err := client.ListUserTeams(opt)
		if resp.StatusCode == 404 {
			// Token doesn't have permissions to query teams. Not sure why this isn't a 403.
			return nil
		}
		if err != nil {
			return err
		}
		for _, team := range teams {
			ui.Groups = append(ui.Groups, "github:"+team.Organization.GetLogin()+":"+team.GetSlug())
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return nil
}

func authenticate(r *http.Request) (*authentication.UserInfo, error) {
	// Create the client to talk to GitHub.
	ts, err := authenticationToken(r)
	if err != nil {
		return nil, err
	}
	client, err := newGithubClient(ts)
	if err != nil {
		return nil, err
	}

	// Run checks for authn and authz.
	ui := &authentication.UserInfo{}
	err = checkUser(client, ui)
	if err != nil {
		return nil, err
	}
	err = checkOrgs(client, ui)
	if err != nil {
		return nil, err
	}
	err = checkTeams(client, ui)
	if err != nil {
		return nil, err
	}
	return ui, nil
}

func authenticationHandler(w http.ResponseWriter, r *http.Request) {
	ui, err := authenticate(r)
	if err != nil {
		log.Printf("[Error] %s", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"apiVersion": "authentication.k8s.io/v1beta1",
			"kind":       "TokenReview",
			"status": authentication.TokenReviewStatus{
				Authenticated: false,
				Error:         err.Error(),
			},
		})
	} else {
		log.Printf("[Success] login as %s; groups %s", ui.Username, strings.Join(ui.Groups, ", "))
		w.WriteHeader(http.StatusOK)
		trs := authentication.TokenReviewStatus{
			Authenticated: true,
			User:          *ui,
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"apiVersion": "authentication.k8s.io/v1beta1",
			"kind":       "TokenReview",
			"status":     trs,
		})
	}
}

func main() {
	bindAddress := ":3000"
	if port, ok := os.LookupEnv("PORT"); ok {
		bindAddress = ":" + port
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", authenticationHandler)
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	srv := &http.Server{
		Addr:         bindAddress,
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	log.Fatal(srv.ListenAndServeTLS("/etc/ssl/webhook/tls.crt", "/etc/ssl/webhook/tls.key"))
}
