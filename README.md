# provider側の設定
## Google
### GCP
- [認証情報](https://console.cloud.google.com/apis/credentials)から新しく認証情報を作成する
- クレデンシャル情報をJSONでダウンロードする
- 必要に応じてスコープを追加する
- 承認済みのJavaScript生成元を追加する
  - オリジンを指定する
  - ローカルで動かす場合は`http://localhost:8080`
- 承認済みのリダイレクトURIを追加する
  - Googleの認証用サーバーからのレスポンスを受け取るURI

## Apple
- [Go Sign In with Apple](https://github.com/Timothylock/go-signin-with-apple)を使う
  - teamID
    - Developer Accountの[メンバーシップの詳細](https://developer.apple.com/account#MembershipDetailsCard)
  - clientID
    - Sign in with Appleを使う場合は **Service ID** を入れる必要がある
      - [identifiers](https://developer.apple.com/account/resources/identifiers/list)から登録する
      - 登録後にIdentifierをクリックすると、 **Sign In with Apple** があるので、Enabledにする
        - DomainとRedirect URIを設定する
        - localhostやローカルIPは **設定できない** ので注意
  - keyID
    - [keys](https://developer.apple.com/account/resources/authkeys/list)から登録する
    - 


# 実装
## ライブラリ
https://pkg.go.dev/golang.org/x/oauth

## 