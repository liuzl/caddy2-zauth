package zauth

import (
	"net/http"
	"strings"

	"github.com/golang/glog"
	"github.com/liuzl/store"
	"zliu.org/goutil"
)

func (m *Middleware) addAccountHandler(w http.ResponseWriter, r *http.Request) {
	glog.Infof("addr=%s  method=%s host=%s uri=%s",
		r.RemoteAddr, r.Method, r.Host, r.RequestURI)
	r.ParseForm()
	uname := strings.TrimSpace(r.FormValue("uname"))
	ak := goutil.GenerateRandomString(20)
	sk := goutil.GenerateRandomString(40)
	account := &Account{Uname: uname, AccessKey: ak, SecretKey: sk}
	b, err := store.ObjectToBytes(account)
	if err != nil {
		glog.Fatal(err)
	}
	err = m.getAuthDB().Put(ak, b)
	glog.Infof("new account: uname=%s, ak=%s, sk=%s", uname, ak, sk)
	ret := MakeResponse(err, "", account)
	MustEncode(w, ret)
}

func (m *Middleware) getAllAccountsHandler(w http.ResponseWriter, r *http.Request) {
	glog.Infof("addr=%s  method=%s host=%s uri=%s",
		r.RemoteAddr, r.Method, r.Host, r.RequestURI)
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
	http.HandleFunc("/api/add_account", m.addAccountHandler)
	http.HandleFunc("/api/get_all_accounts", m.getAllAccountsHandler)
	glog.Info("zauth admin server listen on ", m.AuthAdminAddr)
	glog.Error(http.ListenAndServe(m.AuthAdminAddr, nil))
}
