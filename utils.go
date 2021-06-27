package zauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/juju/errors"
	"github.com/liuzl/store"
	"github.com/rs/zerolog"
)

type ctxKey struct{}

func GetZlog(ctx context.Context) *zerolog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*zerolog.Logger); ok {
		return l
	}

	ret := zerolog.Nop()
	return &ret
}

func ZlogWithContext(ctx context.Context, l *zerolog.Logger) context.Context {
	if lp, ok := ctx.Value(ctxKey{}).(*zerolog.Logger); ok {
		if lp == l {
			// Do not store same logger.
			return ctx
		}
	}
	return context.WithValue(ctx, ctxKey{}, l)
}

func encrypt(sk, msg []byte) string {
	hash := hmac.New(sha256.New, sk)
	hash.Write(msg)
	return hex.EncodeToString(hash.Sum(nil))
}

func genMsg(r *http.Request) ([]byte, error) {
	var msg string
	// Method
	msg += r.Method + "\n"
	// URI
	msg += r.URL.Path + "\n"

	// Query
	var keys []string
	urlVals, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, err
	}
	for k, _ := range urlVals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var params string
	for i, k := range keys {
		if i != 0 {
			params += "&"
		}
		params += k + "=" + url.QueryEscape(urlVals.Get(k))
	}
	msg += params + "\n"

	// Headers
	creditAuth, _ := ParseAuth(r.Header.Get("Authorization"))
	var headerKeys []string
	lowerHeader := make(map[string]string)
	for k, _ := range r.Header {
		lowerHeader[strings.ToLower(k)] = r.Header.Get(k)
	}
	defaultHeaderKeys := []string{"content-length", "content-type", "content-md5", "credit-.*"}
	if len(creditAuth.SignHeaders) != 0 {
		headerKeys = creditAuth.SignHeaders
	} else {
		for k, _ := range lowerHeader {
			for _, dk := range defaultHeaderKeys {
				if match, _ := regexp.Match(dk, []byte(k)); match {
					headerKeys = append(headerKeys, k)
				}
			}
		}
	}
	sort.Strings(headerKeys)

	for _, k := range headerKeys {
		var val string
		if k == "host" {
			val = url.QueryEscape(strings.TrimSpace(r.Host))
		} else {
			val = url.QueryEscape(strings.TrimSpace(lowerHeader[k]))
		}
		msg += k + ":" + val + "\n"
	}
	msg = strings.TrimSpace(msg)
	return []byte(msg), nil
}

func genSignKey(sk []byte, r *http.Request) []byte {
	creditAuth, _ := ParseAuth(r.Header.Get("Authorization"))
	return []byte(encrypt(sk, []byte(creditAuth.Prefix())))
}

type bufferedBody struct {
	*bytes.Reader
}

func (*bufferedBody) Close() error {
	return nil
}

func (m *Middleware) authorize(r *http.Request) (bool, error) {
	ctx := r.Context()
	zlog := zerolog.Ctx(ctx)
	hashlog := GetZlog(ctx)
	creditAuth, err := ParseAuth(r.Header.Get("Authorization"))
	if err != nil {
		return false, err
	}
	// log ak
	zlog.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("access_key", creditAuth.Ak)
	})
	hashlog.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("access_key", creditAuth.Ak)
	})
	// TODO: check version

	// check content-md5
	if len(creditAuth.SignHeaders) == 0 ||
		Contains(creditAuth.SignHeaders, "content-md5") {
		contentType := r.Header.Get("Content-Type")
		contentMD5 := r.Header.Get("Content-MD5")
		if contentType != "" && !strings.Contains(contentType, "Multipart") &&
			!strings.Contains(contentType, "Message") && contentMD5 != "" {
			body, _ := ioutil.ReadAll(r.Body)
			r.Body.Close()
			r.Body = &bufferedBody{
				Reader: bytes.NewReader(body),
			}
			h := md5.New()
			h.Write(body)
			if contentMD5 != hex.EncodeToString(h.Sum(nil)) {
				return false, NoAuthorizationErr
			}
		}
	}

	var curTs time.Time
	curTs = time.Now()
	if creditAuth.Ts.Add(300*time.Second).Before(curTs) ||
		creditAuth.Ts.After(curTs.Add(time.Duration(creditAuth.Expire+300)*time.Second)) {
		return false, ExpiredRequestErr
	}

	var msg []byte
	msg, err = genMsg(r)

	var b []byte
	if b, err = m.getAuthDB().Get(creditAuth.Ak); err != nil {
		if err.Error() == "leveldb: not found" {
			return false, NoAuthorizationErr
		} else {
			return false, errors.Trace(err)
		}
	}

	account := new(Account)
	if err = store.BytesToObject(b, account); err != nil {
		return false, errors.Trace(err)
	}

	// log uname
	zlog.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("uname", account.Uname)
	})
	hashlog.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("uname", account.Uname)
	})
	signKey := genSignKey([]byte(account.SecretKey), r)
	if encrypt(signKey, msg) != creditAuth.Signature {
		return false, NoAuthorizationErr
	}
	return true, nil
}

func MakeResponse(err error, msg string, data interface{}) *RestMessage {
	if err != nil {
		if len(msg) == 0 {
			msg = err.Error()
		}
		var code string
		switch errors.Cause(err) {
		case EmptyParamsErr:
			code = "EMPTY_PARAMETER_ERROR"
		case InsufficientBalanceErr:
			code = "INSUFFICIENT_BALANCE"
		case InvalidParamsErr:
			code = "INVALID_PARAMETER_ERROR"
		case ExpiredRequestErr:
			code = "EXPIRED_REQUEST"
		case NoAuthorizationErr:
			code = "NO_AUTHORIZATION"
		default:
			code = "RETRY_LATER"
			// don't expose inter error
			msg = "Service is not available right now, please try again later"
		}
		return &RestMessage{code, msg}
	} else {
		return &RestMessage{"OK", data}
	}
}

func ParseAuth(authorization string) (*Authorization, error) {
	if !strings.HasPrefix(authorization, AuthTagPrefix) {
		return nil, InvalidParamsErr
	}
	creditAuthParts := strings.Split(authorization, "/")
	if len(creditAuthParts) != 6 {
		return nil, InvalidParamsErr
	}
	expire, err := strconv.ParseInt(creditAuthParts[3], 10, 64)
	if err != nil {
		return nil, InvalidParamsErr
	}
	var ts time.Time
	ts, err = time.Parse("2006-01-02T15:04:05Z", creditAuthParts[2])
	if err != nil {
		return nil, InvalidParamsErr
	}
	var headers []string
	if creditAuthParts[4] != "" {
		headers = strings.Split(creditAuthParts[4], ";")
	}
	return &Authorization{
		Tag:         creditAuthParts[0][:strings.LastIndex(creditAuthParts[0], "-")],
		Version:     creditAuthParts[0][strings.LastIndex(creditAuthParts[0], "-")+2 : len(creditAuthParts[0])],
		Ak:          creditAuthParts[1],
		Ts:          ts,
		Expire:      expire,
		SignHeaders: headers,
		Signature:   creditAuthParts[5],
	}, nil
}

func (auth *Authorization) String() string {
	return fmt.Sprintf(
		"%s-v%s/%s/%s/%d/%s/%s",
		auth.Tag, auth.Version,
		auth.Ak, auth.Ts.Format("2006-01-02T15:04:05Z"),
		auth.Expire,
		strings.Join(auth.SignHeaders, ";"),
		auth.Signature)
}

func (auth *Authorization) Prefix() string {
	return fmt.Sprintf(
		"%s-v%s/%s/%s/%d",
		auth.Tag, auth.Version,
		auth.Ak, auth.Ts.Format("2006-01-02T15:04:05Z"),
		auth.Expire)
}

func Contains(arr []string, val string) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}

type RestMessage struct {
	Status  string      `json:"status"`
	Message interface{} `json:"message"`
}

func MustEncode(w http.ResponseWriter, i interface{}) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-type", "application/json;charset=utf-8")
	e := json.NewEncoder(w)
	if err := e.Encode(i); err != nil {
		//panic(err)
		e.Encode(err.Error())
	}
}
