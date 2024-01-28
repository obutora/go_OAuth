package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	v2 "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/joho/godotenv"
)

var (
	googleClientID string
	googleClientSecret string
	googleProjectID string

	appleTeamId string
	appleClientId string
	appleKeyId string
	appleSecret string
)

func init() {
	if err := godotenv.Load("secret/.env"); err != nil {
		log.Printf("failed to load .env file: %s", err.Error())
	}

		// Projectごとに設定すべきクレデンシャル群
		googleClientID = os.Getenv("GOOGLE_CLIENT_ID")
		googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
		googleProjectID = os.Getenv("GOOGLE_PROJECT_ID")

		appleTeamId = os.Getenv("APPLE_TEAM_ID")
		appleClientId = os.Getenv("APPLE_CLIENT_ID")
		appleKeyId = os.Getenv("APPLE_KEY_ID")
		appleSecret = os.Getenv("APPLE_SECRET")
}



func main() {
	googleConfig, err := NewGoogleOAuthConfig()
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Route("/client", func(r chi.Router) {
		r.Get("/gmail", func(w http.ResponseWriter, r *http.Request) {
			url := googleConfig.AuthCodeURL("state", oauth2.AccessTypeOffline) // TODO stateの値を変更 + AccessTypeを変更
			// http.Redirect(w, r, url, http.StatusFound)

			render.Status(r, http.StatusOK)
			render.JSON(w, r, map[string]string{"url": url})
		})

		r.Get("/apple", func(w http.ResponseWriter, r *http.Request) {
			state := "state" // TODO stateの値を変更
			url := fmt.Sprintf("https://appleid.apple.com/auth/authorize?response_type=code&client_id=%v&redirect_uri=YOUR_REDIRECT_URI&state=%v&scope=name email", appleClientId, state)
			
			render.Status(r, http.StatusOK)
			render.JSON(w, r, map[string]string{"url": url})
		})
	})

	r.Route("/auth", func(r chi.Router) {
		r.Get("/google", func(w http.ResponseWriter, r *http.Request) {
			code := r.URL.Query().Get("code")
			state := r.URL.Query().Get("state")
			log.Printf("code: %s, state: %s", code, state)

			// TODO stateの検証

			token, err := googleConfig.Exchange(r.Context(), code)
			if err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, map[string]string{"error": err.Error()})
			}

			userInfo, err := UserInfoFromGoogleAccessToken(r.Context(), googleConfig, token)

			render.Status(r, http.StatusOK)

			// TODO 実際はレスポンスで返すのではなく、DBに保存してJWT発行する
			render.JSON(w, r, map[string]string{
				"token": token.AccessToken,
				"email": userInfo.Email,
				"uid": userInfo.Id,
		})
		
		})
	})

	log.Printf("listen: %s", "8080")
    if err := http.ListenAndServe("localhost:8080", r); err != nil {
        log.Fatalf("!! %+v", err)
    }
}


// クレデンシャルを利用してOAuthの設定を作成
func NewGoogleOAuthConfig() (*oauth2.Config, error) {
	cred := fmt.Sprintf(`
	{
		"web": {
			"client_id": "%v",
			"project_id": "%v",
			"auth_uri": "https://accounts.google.com/o/oauth2/auth",
			"token_uri": "https://oauth2.googleapis.com/token",
			"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
			"client_secret": "%v",
			"redirect_uris": [
				"http://localhost:8080/auth/google"
			],
			"javascript_origins": [
				"http://localhost:8080"
			]
		}
	}
	`, googleClientID, googleProjectID, googleClientSecret)

	r := strings.ReplaceAll(cred, "\n", "")
	credBytes := []byte(r)
	
	config, err := google.ConfigFromJSON(credBytes, "https://www.googleapis.com/auth/userinfo.email")
	if err != nil {
		return nil, err
	}
	return config, nil
}

func UserInfoFromGoogleAccessToken(ctx context.Context,config *oauth2.Config, token *oauth2.Token)(*v2.Userinfo , error) {
	service, err := v2.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))
	if err != nil {
		return nil, err
	}

	return service.Userinfo.Get().Do()
}