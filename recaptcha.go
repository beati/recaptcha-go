// Package recaptcha implements verification of reCaptcha form submissions.
//
// See https://www.google.com/recaptcha for more information about reCaptcha.
package recaptcha

import (
	"bufio"
	"errors"
	"net/http"
	"net/url"
)

// Verify determine the validity of a reCaptcha form submission. If the
// submission is valid it returns a nil error value, otherwise it returns a
// non-nil error value.
//
// See https://developers.google.com/recaptcha for more details
func Verify(privateKey, remoteIP, challenge, response string, c *http.Client) error {

	if challenge == "" || response == "" {
		return errors.New("empty challenge and response")
	}

	if c == nil {
		c = http.DefaultClient
	}
	const recaptchaURL = "https://www.google.com/recaptcha/api/verify"
	params := url.Values{
		"privatekey": {privateKey},
		"remoteip":   {remoteIP},
		"challenge":  {challenge},
		"response":   {response},
	}
	resp, err := client.PostForm(recaptchaURL, params)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	if !scanner.Scan() {
		return scanner.Err()
	}
	if scanner.Text() == "true" {
		return nil
	}

	if !scanner.Scan() {
		return scanner.Err()
	}
	return errors.New(scanner.Text())
}
