package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mxschmitt/playwright-go"
	"github.com/tvandinther/go-openconnect-sso/config"
)

var log *slog.Logger

func main() {
	var (
		server    = flag.String("server", "", "the OpenConnect VPN server address")
		ocFile    = flag.String("config", "", "where the OpenConnect config file will be saved")
		logFormat = flag.String("log-format", "text", "log format (json or text)")
		logLevel  = flag.String("log-level", "info", "log level [WARNING: 'debug' level will print openconnect login cookie to the console] (info, warn, error, debug, none)")
	)
	flag.Parse()

	log = setupLogger(*logFormat, *logLevel)
	log.Info("Logger initialized")

	pw, err := playwright.Run()
	if err != nil {
		log.Error("could not launch playwright", "err", err)
	}
	browser, err := pw.Firefox.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(false),
	})
	if err != nil {
		log.Error("could not launch Firefox", "err", err)
	}
	context, err := browser.NewContext()
	if err != nil {
		log.Error("could not create context", "err", err)
	}
	page, err := context.NewPage()
	if err != nil {
		log.Error("could not create page", "err", err)
	}

	initResp, targetVPNServer := initializationStage(*server)

	log.Info("waiting to detect successful authentication token cookie on the browser")
	page.Goto(initResp.LoginURL)

	var tokenCookie playwright.NetworkCookie

	for {
		foundCookie := false
		cookies, err := context.Cookies()
		if err != nil {
			log.Error("could not get cookies from browser context", "err", err)
		}

		for _, cookie := range cookies {
			if cookie.Name == initResp.TokenCookieName {
				tokenCookie = *cookie
				log.Info("received successful authentication token cookie from browser")
				foundCookie = true
				break
			}
		}
		if foundCookie {
			browser.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	finalResp := finalizationStage(targetVPNServer, tokenCookie.Value, initResp.Opaque.Value)
	log.Info("received openconnect server fingerprint and connection cookie successfully")

	writeOCConfig(finalResp.Cookie, finalResp.Fingerprint, targetVPNServer, *ocFile)
}

func setupLogger(format, level string) *slog.Logger {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	case "none":
		// Custom "none" level: set to a high level to suppress logs
		slogLevel = slog.Level(100)
	default:
		slogLevel = slog.LevelInfo
	}

	handlerOpts := &slog.HandlerOptions{
		Level: slogLevel,
	}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
	case "text":
		handler = slog.NewTextHandler(os.Stderr, handlerOpts)
	default:
		handler = slog.NewTextHandler(os.Stderr, handlerOpts)
	}

	// Add timestamp and source info
	handler = handler.WithAttrs([]slog.Attr{
		slog.String("ts", "utc"),
	})

	logger := slog.New(handler)

	return logger
}

func initializationStage(url string) (config.InitializationResponse, string) {
	log = log.With("stage", "initialization")

	// Get the final redirect-url from the initial server
	resp, err := http.Get(url)
	if err != nil {
		log.Error("Failed to get url", "url", url, "err", err)
		os.Exit(1)
	}
	targetVPNServer := resp.Request.URL.String()

	// Begin the authentication process: stage-1
	xmlPayload := fmt.Sprintf(`
    <config-auth client="vpn" type="init" aggregate-auth-version="2">
      <version who="vpn">4.7.00136</version>
      <device-id>linux-64</device-id>
      <group-select></group-select>
			<group-access>%s</group-access>
      <capabilities>
        <auth-method>single-sign-on-v2</auth-method>
      </capabilities>
    </config-auth>
	`, targetVPNServer)
	log.Debug("configuring VPN request", "targetVPNServer", targetVPNServer)

	var result config.InitializationResponse
	body := makePostReq(xmlPayload, targetVPNServer)

	log.Debug("received response from server", "body", string(body))

	if err := xml.Unmarshal(body, &result); err != nil {
		log.Error("failed to unmarshal the received response body to XML", "err", err, "body", string(body))
		os.Exit(1)
	}

	log.Info("unmarshalled init response", "loginURL", result.LoginURL, "loginFinalURL", result.LoginFinalURL, "tokenCookieName", result.TokenCookieName, "opaque", result.Opaque.Value)
	return result, targetVPNServer
}

func finalizationStage(vpnServer string, token string, configHash string) config.FinalizationResponse {
	log = log.With("stage", "finalization")

	xmlPayload := fmt.Sprintf(`
    <config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
      <version who="vpn">4.7.00136</version>
      <device-id>linux-64</device-id>
      <session-token/>
      <session-id/>
      <opaque is-for="sg">%s</opaque>
      <auth>
        <sso-token>%s</sso-token>
      </auth>
      </config-auth>
  `, configHash, token)

	var result config.FinalizationResponse
	body := makePostReq(xmlPayload, vpnServer)

	log.Debug("received response from server", "body", string(body))

	if err := xml.Unmarshal(body, &result); err != nil {
		log.Error("failed to unmarshal the received response body to XML", "err", err, "body", string(body))
		os.Exit(1)
	}

	log.Debug("unmarshalled final response", "cookie", result.Cookie, "fingerprint", result.Fingerprint)
	return result
}

func makePostReq(xmlPayload, server string) []byte {

	req, err := http.NewRequest("POST", server, strings.NewReader(xmlPayload))
	if err != nil {
		log.Error("Failed to create http request", "err", err)
		os.Exit(1)
	}
	headers := map[string]string{
		"User-Agent":          "AnyConnect Linux_64 4.7.00136",
		"Accept":              "*/*",
		"Accept-Encoding":     "identity",
		"X-Transcend-Version": "1",
		"X-Aggregate-Auth":    "1",
		"X-Support-HTTP-Auth": "true",
		"Content-Type":        "application/x-www-form-urlencoded",
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("failed to POST request to the server", "server", req.URL.String(), "err", err)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	log.Info("successfullly received response from server", "url", resp.Request.URL.String())
	log.Debug("received response", "body", string(body), "url", resp.Request.URL.String())

	return body
}

func writeOCConfig(cookie, fingerprint, server, ocFile string) {
	content := fmt.Sprintf("cookie=%s\nservercert=%s\n# host=%s\n", cookie, fingerprint, server)
	if err := os.WriteFile(ocFile, []byte(content), 0600); err != nil {
		log.Error("failed to write authentication details to file", "file", ocFile, "err", err)
		os.Exit(1)
	}
	log.Info("successfully written authentication details to file", "file", ocFile)
}
