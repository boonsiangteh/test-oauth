package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"fmt"
	"log"
	"os"

	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var conf = &oauth2.Config{
	ClientID:     "960d9cbc4263c2d7102a",
	ClientSecret: "73503be1be93606171c6f63d81b2b7bb0ba72490",
	Endpoint:     github.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/github/receive",
}

var state = "somesteadystate"
var pkce_verifier = oauth2.GenerateVerifier()
var githubAPI = "https://api.github.com"

// to hold all registered users with key = uid and value = email
var oauthRegisteredUsers = make(map[string]string)

type user struct {
	Name  string
	Email string
}

// example user database key is email and value is first name
var userDB = map[string]user{}

// to keep track of user sessions (key is signedSessionToken and value is email )
var userSessions = make(map[string]string)

var signingKey = []byte("mysigningkey")

func (s *Server) RegisterRoutes() http.Handler {

	r := gin.Default()
	path, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("path: ", path)
	r.LoadHTMLGlob("internal/templates/*")
	r.GET("/", s.indexHandler)
	r.POST("/oauth/github/login", s.oauthGithubHandler)
	r.GET("/oauth/github/receive", s.oauthGithubReceiver)
	r.GET("/partial-register", s.partialRegister)
	r.POST("/oauth/github/register", s.oauthGithubRegister)

	return r
}

func (s *Server) indexHandler(c *gin.Context) {

	fmt.Println("%v", userSessions)

	// check if user is logged in by checking user session token
	signedSessionToken, err := c.Cookie("token")
	if err != nil {
		log.Println("problem getting token from cookie")
	}

	sessionID, err := parseToken(signedSessionToken)
	log.Println("indexhandler sessionID: ", sessionID)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("error parsing sessiontoken in indexHandler"))
	}

	email := userSessions[sessionID]
	name := userDB[email].Name

	log.Println("indexHandler email: ", email)
	log.Println("indexHandler name: ", name)

	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"email": email,
		"name":  name,
	})
	return
}

func (s *Server) oauthGithubHandler(c *gin.Context) {
	// resp := make(map[string]string)
	// resp["message"] = "Hello World"

	// pkce verifier
	url := conf.AuthCodeURL(state, oauth2.S256ChallengeOption(pkce_verifier))
	fmt.Println("Auth Url: " + url)

	c.Redirect(http.StatusSeeOther, url)
	return
}

func (s *Server) oauthGithubReceiver(c *gin.Context) {
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
		log.Fatal("error exchanging token: ", err)
	}
	ts := conf.TokenSource(c.Request.Context(), token)

	fmt.Println("%+v", token)

	oauthClient := oauth2.NewClient(c.Request.Context(), ts)

	oauthresp, err := oauthClient.Get(githubAPI + "/user")
	if err != nil {
		log.Fatal("error getting user profile: ", err)
	}

	bs, err := io.ReadAll(oauthresp.Body)
	oauthresp.Body.Close()
	fmt.Println()
	fmt.Println("user orofile: " + string(bs))

	type githubUserProfile struct {
		Login             string      `json:"login"`
		ID                int         `json:"id"`
		NodeID            string      `json:"node_id"`
		AvatarURL         string      `json:"avatar_url"`
		GravatarID        string      `json:"gravatar_id"`
		URL               string      `json:"url"`
		HTMLURL           string      `json:"html_url"`
		FollowersURL      string      `json:"followers_url"`
		FollowingURL      string      `json:"following_url"`
		GistsURL          string      `json:"gists_url"`
		StarredURL        string      `json:"starred_url"`
		SubscriptionsURL  string      `json:"subscriptions_url"`
		OrganizationsURL  string      `json:"organizations_url"`
		ReposURL          string      `json:"repos_url"`
		EventsURL         string      `json:"events_url"`
		ReceivedEventsURL string      `json:"received_events_url"`
		Type              string      `json:"type"`
		SiteAdmin         bool        `json:"site_admin"`
		Name              string      `json:"name"`
		Company           string      `json:"company"`
		Blog              string      `json:"blog"`
		Location          interface{} `json:"location"`
		Email             string      `json:"email"`
		Hireable          bool        `json:"hireable"`
		Bio               interface{} `json:"bio"`
		TwitterUsername   interface{} `json:"twitter_username"`
		PublicRepos       int         `json:"public_repos"`
		PublicGists       int         `json:"public_gists"`
		Followers         int         `json:"followers"`
		Following         int         `json:"following"`
		CreatedAt         time.Time   `json:"created_at"`
		UpdatedAt         time.Time   `json:"updated_at"`
	}

	var userProfile githubUserProfile
	err = json.Unmarshal(bs, &userProfile)
	if err != nil {
		fmt.Fprintf(c.Writer, "error unmarshalling json to struct: %s", err)
	}

	fmt.Println("email of user profile is : ", userProfile.Email)

	// check to see if user is registered with our website via this oauth provider yet
	email, ok := oauthRegisteredUsers[strconv.Itoa(userProfile.ID)]
	if !ok {
		// this means the user is not registered with us yet via github,
		// so we will redirect them to another page to register with us and prepopulate their details we obtained from github
		// we will also create a jwt token in order to create a session
		fmt.Println("user does not exist")
		signedJWTToken, err := createToken(strconv.Itoa(userProfile.ID))
		if err != nil {
			fmt.Println("cant create token for user: ", err)
			c.Redirect(http.StatusInternalServerError, "/msg="+email)
		}

		// embed all necessary values in url param and redirect to url
		uv := url.Values{}

		uv.Add("sst", signedJWTToken)
		uv.Add("email", userProfile.Email)
		uv.Add("name", userProfile.Name)
		c.Redirect(http.StatusSeeOther, "/partial-register?"+uv.Encode())
	}

	return
	// if user is already registered with us via github, create session and redirect to home page and display all their details

}

func (s *Server) partialRegister(c *gin.Context) {
	// let users register in our app if they're not registered yet but prepopulate info
	// with the info we got from oauth provider when they login via oauth provider
	sst := c.Query("sst")
	name := c.Query("name")
	email := c.Query("email")
	fmt.Println(sst)
	fmt.Println(name)
	fmt.Println(email)
	c.HTML(http.StatusOK, "partial-register.tmpl", gin.H{
		"sst":   sst,
		"name":  name,
		"email": email,
	})

	return
}

func parseToken(token string) (string, error) {
	// parses the token and reurns the userId claim contained in the custom claim
	parsedToken, err := jwt.ParseWithClaims(token, &MyCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("diff alg between signed token and what our app expected")
		}
		return signingKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("cannot parse token due to: %w", err)
	}

	return parsedToken.Claims.(*MyCustomClaims).ID, nil
}

func createSession(email string) (string, error) {
	// this creates a random session id and generates a signed session token

	log.Println("======creating user session======")

	sID := uuid.New().String()

	// we keep track of user's session by tracking their session id and email
	userSessions[sID] = email

	fmt.Println("user sessions : %v", userSessions)

	signedSID, err := createToken(sID)

	if err != nil {
		return "", fmt.Errorf("cant create session token: %w", err)
	}

	//return the signed session token so that we can then parse it to
	// ensure that the session token is still valid and not expired yet
	return signedSID, nil

}

func (s *Server) oauthGithubRegister(c *gin.Context) {
	// register the user. Create token and populate user info into userDB
	name := c.PostForm("name")
	if name == "" {
		log.Println("name is empty")
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("name is empty"))
	}

	email := c.PostForm("email")
	if email == "" {
		log.Println("email is empty")
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("email is empty"))
	}

	signedJWTToken := c.PostForm("sst")
	if signedJWTToken == "" {
		log.Println("sst is empty")
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("sst is empty"))
	}

	userId, err := parseToken(signedJWTToken)
	if err != nil {
		fmt.Println("error parsing token in oauthGithubRegister: ", err)
	}

	// once they register as our user, add them into our user db
	userDB[email] = user{
		Name:  name,
		Email: email,
	}

	// also keep track of them as our user who registered via oauth
	oauthRegisteredUsers[userId] = email

	// create a session to keep track of their session so we can expire them when the session token expires
	signedSessionToken, err := createSession(email)
	c.SetCookie("token", signedSessionToken, 3600, "/", "localhost", false, true)
	c.Redirect(http.StatusSeeOther, "/")
}
