package server

import (
	"net/http"

	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var conf = &oauth2.Config{
	ClientID:     "960d9cbc4263c2d7102a",
	ClientSecret: "73503be1be93606171c6f63d81b2b7bb0ba72490",
	Endpoint:     github.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/amazon/receive",
}

var state = "somesteadystate"
var pkce_verifier = oauth2.GenerateVerifier()

func (s *Server) RegisterRoutes() http.Handler {

	r := gin.Default()
	path, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}
	fmt.Println("path: ", path)
	r.LoadHTMLGlob("internal/templates/*")
	r.GET("/", s.HelloWorldHandler)
	r.POST("/oauth/amazon/login", s.oauthAmazonHandler)
	r.GET("/oauth/amazon/receive", s.oauthAmazonReceiver)

	return r
}

func (s *Server) HelloWorldHandler(c *gin.Context) {
	resp := make(map[string]string)
	resp["message"] = "Hello World"

	// c.JSON(http.StatusOK, resp)
	c.HTML(http.StatusOK, "index.html", nil)
}

func (s *Server) oauthAmazonHandler(c *gin.Context) {
	// resp := make(map[string]string)
	// resp["message"] = "Hello World"

	// pkce verifier
	url := conf.AuthCodeURL(state, oauth2.S256ChallengeOption(pkce_verifier))
	fmt.Println("Auth Url: " + url)

	c.Redirect(http.StatusSeeOther, url)

}

func (s *Server) oauthAmazonReceiver(c *gin.Context) {
	resp := make(map[string]string)
	code := c.Query("code")
	state := c.Query("state")

	fmt.Println("code: " + code)
	fmt.Println("state: " + state)
	resp["code"] = code
	resp["state"] = state
	// c.JSON(http.StatusOK, resp)

	token, err := conf.Exchange(c.Request.Context(), code, oauth2.VerifierOption(pkce_verifier))
	if err != nil {
		fmt.Println("error exchanging token: ", err)
	}

	fmt.Println("%+v", token)
	c.JSON(200, token)
}
