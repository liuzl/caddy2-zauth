package zauth

import (
	"errors"
	"time"
)

var (
	EmptyParamsErr         = errors.New("Parameter should not be empty")
	InsufficientBalanceErr = errors.New("Insufficient balance")
	InvalidParamsErr       = errors.New("Invalid params")
	ExpiredRequestErr      = errors.New("Expired request")
	NoAuthorizationErr     = errors.New("Authorization failed")

	AuthTagPrefix = "credit-v"
	ApiVersion    = "1.0"
)

type Account struct {
	Uname     string `json:"uname"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

type Authorization struct {
	Tag         string    `json:"tag"`
	Version     string    `json:"version"`
	Ak          string    `json:"ak"`
	Ts          time.Time `json:"timestamp"`
	Expire      int64     `json:"expire"`
	SignHeaders []string  `json:"sign_headers"`
	Signature   string    `json:"signature"`
}
