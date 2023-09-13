package main

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
)

var token = "puocxw5p2h"

// Response response
type Response struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

// VerifySignatureRequest request
type VerifySignatureRequest struct {
	Signature string `form:"signature"`
	Timestamp string `form:"timestamp"`
	Nonce string `form:"nonce"`
	Echostr string `form:"echostr"`
}

func signatureFn(params ...string) string {
	sort.Strings(params)
	h := sha1.New()
	for _, s := range params {
		io.WriteString(h, s)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func verifySignature(signature, timestamp, nonce, echostr string) (string, error) {
	if signature != signatureFn(token, timestamp, nonce) {
		return  "", errors.New("签名不正确")
	}
	return echostr, nil
}

func verifySignatureHandler(c *gin.Context) {
	var params VerifySignatureRequest

	if err := c.ShouldBind(&params); err != nil {
    c.JSON(http.StatusBadRequest, gin.H{
      "code": 1,
      "msg": "服务器错误",
    })
		return
	}

	ret, err := verifySignature(
		params.Signature, 
		params.Timestamp, 
		params.Nonce, 
		params.Echostr,
	)

	if err != nil {
		c.JSON(http.StatusOK, "")
		return
	}

	c.JSON(http.StatusOK, ret)
}

func main() {
  r := gin.Default()
  r.GET("/ping", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
      "message": "pong",
    })
  })
  r.GET("/api/public/wx/op", verifySignatureHandler)
  r.Run(":80")
}
