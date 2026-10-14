// SPDX-License-Identifier: MPL-2.0

package xaisecrets

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	sdktemplate "github.com/hashicorp/vault/sdk/helper/template"
)

const (
	defaultNameTemplate = "vault-{{.RoleName}}-{{.RandomSuffix}}"
	maxKeyNameLength    = 64
)

var (
	invalidNameChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	repeatHyphens    = regexp.MustCompile(`-+`)
)

type nameTemplateData struct {
	RoleName     string
	RandomSuffix string
}

func validateAPIEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("api_endpoint is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("api_endpoint must be an http or https URL")
	}
	if u.Host == "" {
		return fmt.Errorf("api_endpoint must include a host")
	}
	return nil
}

func formatName(templateStr string, data nameTemplateData) (string, error) {
	tmpl, err := sdktemplate.NewTemplate(sdktemplate.Template(templateStr))
	if err != nil {
		return "", fmt.Errorf("invalid name_template: %w", err)
	}
	result, err := tmpl.Generate(data)
	if err != nil {
		return "", fmt.Errorf("error applying name_template: %w", err)
	}
	return result, nil
}

func validateNameTemplate(templateStr string) error {
	if strings.TrimSpace(templateStr) == "" {
		return fmt.Errorf("name_template must not be empty")
	}
	result, err := formatName(templateStr, nameTemplateData{
		RoleName:     "testrole",
		RandomSuffix: "abcdefgh",
	})
	if err != nil {
		return err
	}
	if sanitizeKeyName(result) == "" {
		return fmt.Errorf("name_template produced an empty name")
	}
	return nil
}

func sanitizeKeyName(name string) string {
	name = strings.TrimSpace(name)
	name = invalidNameChars.ReplaceAllString(name, "-")
	name = repeatHyphens.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-_.")
	if len(name) > maxKeyNameLength {
		name = strings.Trim(name[:maxKeyNameLength], "-_.")
	}
	if name == "" {
		return "vault-key"
	}
	return name
}

func generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	const charsetLen = len(charset)
	threshold := 256 - (256 % charsetLen)

	result := make([]byte, length)
	buf := make([]byte, length*2)
	written := 0
	for written < length {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("error generating random bytes: %w", err)
		}
		for _, b := range buf {
			if written == length {
				break
			}
			if int(b) < threshold {
				result[written] = charset[int(b)%charsetLen]
				written++
			}
		}
	}
	return string(result), nil
}
