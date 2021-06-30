package zauth

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/liuzl/store"
	"go.uber.org/zap"
	"zliu.org/goutil"
)

func (m *Middleware) addAccountHandler(w http.ResponseWriter, r *http.Request) {
	caddy.Log().Info("addAccountHandler",
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.String("request_uri", r.RequestURI))
	r.ParseForm()
	uname := strings.TrimSpace(r.FormValue("uname"))
	ak := goutil.GenerateRandomString(20)
	sk := goutil.GenerateRandomString(40)
	account := &Account{Uname: uname, AccessKey: ak, SecretKey: sk}
	b, err := store.ObjectToBytes(account)
	if err != nil {
		caddy.Log().Fatal("fatal error", zap.Error(err))
	}
	err = m.getAuthDB().Put(ak, b)
	caddy.Log().Info("new account",
		zap.String("uname", uname), zap.String("ak", ak), zap.String("sk", sk))
	ret := MakeResponse(err, "", account)
	MustEncode(w, ret)
}

func (m *Middleware) getAllAccountsHandler(w http.ResponseWriter, r *http.Request) {
	caddy.Log().Info("getAllAccountsHandler",
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.String("request_uri", r.RequestURI))

	var accounts []*Account
	err := m.getAuthDB().ForEach(nil, func(key, value []byte) (bool, error) {
		account := new(Account)
		if e := store.BytesToObject(value, account); e != nil {
			return false, e
		}
		accounts = append(accounts, account)
		return true, nil
	})
	ret := MakeResponse(err, "", accounts)
	MustEncode(w, ret)
}

func (m *Middleware) admin() {
	http.HandleFunc("/zauth/add_account", m.addAccountHandler)
	http.HandleFunc("/zauth/get_all_accounts", m.getAllAccountsHandler)
	caddy.Log().Info("zauth admin server started", zap.String("listen", m.AuthAdminAddr))
	caddy.Log().Error("zauth", zap.Error(http.ListenAndServe(m.AuthAdminAddr, nil)))
}
