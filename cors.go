package fasthttpcors

import (
	"bytes"
	"os"
	"strconv"
	"strings"

	"github.com/valyala/fasthttp"
)

// Options is struct that defined cors properties
type Options struct {
	AllowedOrigins   []string
	AllowedHeaders   []string
	AllowMaxAge      int
	AllowedMethods   []string
	ExposedHeaders   []string
	AllowCredentials bool
	Debug            bool
}

type CorsHandler struct {
	allowedOriginsAll bool
	allowedOrigins    []string
	allowedHeadersAll bool
	allowedHeaders    []string
	allowedMethods    []string
	exposedHeaders    []string
	allowCredentials  bool
	maxAge            int
	logger            Logger
}

var defaultOptions = &Options{
	AllowedOrigins: []string{"*"},
	AllowedMethods: []string{"GET", "POST"},
	AllowedHeaders: []string{"Origin", "Accept", "Content-Type"},
}

func DefaultHandler() *CorsHandler {
	return NewCorsHandler(*defaultOptions)
}

func NewCorsHandler(options Options) *CorsHandler {
	cors := &CorsHandler{
		allowedOrigins:   options.AllowedOrigins,
		allowedHeaders:   options.AllowedHeaders,
		allowCredentials: options.AllowCredentials,
		allowedMethods:   options.AllowedMethods,
		exposedHeaders:   options.ExposedHeaders,
		maxAge:           options.AllowMaxAge,
		logger:           OffLogger(),
	}

	if options.Debug {
		cors.logger = NewLogger(os.Stdout)
	}

	if len(cors.allowedOrigins) == 0 {
		cors.allowedOrigins = defaultOptions.AllowedOrigins
		cors.allowedOriginsAll = true
	} else {
		for _, v := range options.AllowedOrigins {
			if v == "*" {
				cors.allowedOrigins = defaultOptions.AllowedOrigins
				cors.allowedOriginsAll = true
				break
			}
		}
	}
	if len(cors.allowedHeaders) == 0 {
		cors.allowedHeaders = defaultOptions.AllowedHeaders
		cors.allowedHeadersAll = true
	} else {
		for _, v := range options.AllowedHeaders {
			if v == "*" {
				cors.allowedHeadersAll = true
				break
			}
		}
	}
	if len(cors.allowedMethods) == 0 {
		cors.allowedMethods = defaultOptions.AllowedMethods
	}
	return cors
}

func (c *CorsHandler) CorsMiddleware(innerHandler fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if string(ctx.Method()) == "OPTIONS" {
			c.handlePreflight(ctx)
			ctx.SetStatusCode(200)
		} else {
			c.handleActual(ctx)
			innerHandler(ctx)
		}
	}
}

func (c *CorsHandler) handlePreflight(ctx *fasthttp.RequestCtx) {
	originHeader := ctx.Request.Header.Peek("Origin")
	if len(originHeader) == 0 || c.isAllowedOrigin(originHeader) == false {
		c.logger.Log("Origin ", originHeader, " is not in", c.allowedOrigins)
		return
	}
	method := ctx.Request.Header.Peek("Access-Control-Request-Method")
	if !c.isAllowedMethod(method) {
		c.logger.Log("Method ", string(method), " is not in", c.allowedMethods)
		return
	}
	headers := [][]byte{}
	if len(ctx.Request.Header.Peek("Access-Control-Request-Headers")) > 0 {
		headers = bytes.Split(ctx.Request.Header.Peek("Access-Control-Request-Headers"), []byte(","))
	}
	if !c.areHeadersAllowed(headers) {
		c.logger.Log("Headers ", string(bytes.Join(headers, []byte(","))), " is not in", c.allowedHeaders)
		return
	}

	ctx.Response.Header.SetBytesV("Access-Control-Allow-Origin", originHeader)
	ctx.Response.Header.SetBytesV("Access-Control-Allow-Methods", method)
	if len(headers) > 0 {
		ctx.Response.Header.SetBytesV("Access-Control-Allow-Headers", bytes.Join(headers, []byte(", ")))
	}
	if c.allowCredentials {
		ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
	}
	if c.maxAge > 0 {
		ctx.Response.Header.Set("Access-Control-Max-Age", strconv.Itoa(c.maxAge))
	}
}

func (c *CorsHandler) handleActual(ctx *fasthttp.RequestCtx) {
	originHeader := ctx.Request.Header.Peek("Origin")
	if len(originHeader) == 0 || c.isAllowedOrigin(originHeader) == false {
		c.logger.Log("Origin ", string(originHeader), " is not in", c.allowedOrigins)
		return
	}
	ctx.Response.Header.SetBytesV("Access-Control-Allow-Origin", originHeader)
	if len(c.exposedHeaders) > 0 {
		ctx.Response.Header.Set("Access-Control-Expose-Headers", strings.Join(c.exposedHeaders, ", "))
	}
	if c.allowCredentials {
		ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
	}
}

func (c *CorsHandler) isAllowedOrigin(originHeader []byte) bool {
	if c.allowedOriginsAll {
		return true
	}
	for _, val := range c.allowedOrigins {
		if val == string(originHeader) {
			return true
		}
	}
	return false
}

func (c *CorsHandler) isAllowedMethod(methodHeader []byte) bool {
	if len(c.allowedMethods) == 0 {
		return false
	}
	if string(methodHeader) == "OPTIONS" {
		return true
	}
	for _, m := range c.allowedMethods {
		if m == string(methodHeader) {
			return true
		}
	}
	return false
}

func (c *CorsHandler) areHeadersAllowed(headers [][]byte) bool {
	if c.allowedHeadersAll || len(headers) == 0 {
		return true
	}
	for _, header := range headers {
		found := false
		for _, h := range c.allowedHeaders {
			if h == string(header) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
