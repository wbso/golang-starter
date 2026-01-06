package email

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/wbso/golang-starter/internal/config"
)

// Email represents an email message
type Email struct {
	To      string
	Subject string
	Body    string
}

// Service handles email sending
type Service struct {
	config  config.EmailConfig
	auth    smtp.Auth
	tmplDir string
}

// New creates a new email service
func New(cfg config.EmailConfig) *Service {
	var auth smtp.Auth
	if cfg.User != "" && cfg.Password != "" {
		auth = smtp.PlainAuth("", cfg.User, cfg.Password, cfg.Host)
	}

	return &Service{
		config:  cfg,
		auth:    auth,
		tmplDir: "email/templates",
	}
}

// Send sends an email
func (s *Service) Send(email *Email) error {
	// Format message
	msg := fmt.Sprintf("From: %s <%s>\r\n", s.config.FromName, s.config.From)
	msg += fmt.Sprintf("To: %s\r\n", email.To)
	msg += fmt.Sprintf("Subject: %s\r\n", email.Subject)
	msg += "MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n"
	msg += email.Body

	// Send email
	addr := fmt.Sprintf("%s:%s", s.config.Host, s.config.Port)

	// TLS configuration
	if s.config.Port == "465" {
		return s.sendWithTLS(addr, msg, email.To)
	}

	return smtp.SendMail(addr, s.auth, s.config.From, []string{email.To}, []byte(msg))
}

// sendWithTLS sends email using TLS
func (s *Service) sendWithTLS(addr string, msg string, to string) error {
	// Connect to server
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer func() {
		_ = client.Close()
	}()

	// Start TLS
	if err := client.StartTLS(&tls.Config{
		InsecureSkipVerify: false,
		ServerName:         s.config.Host,
	}); err != nil {
		return fmt.Errorf("failed to start TLS: %w", err)
	}

	// Auth
	if s.auth != nil {
		if err := client.Auth(s.auth); err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	// Set sender and recipient
	if err := client.Mail(s.config.From); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	// Send data
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to send data: %w", err)
	}
	defer func() {
		_ = wc.Close()
	}()

	_, err = wc.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// SendEmailVerification sends an email verification email
func (s *Service) SendEmailVerification(to, name, verificationURL string) error {
	body, err := s.renderTemplate("email_verification.html", map[string]string{
		"Name":            name,
		"VerificationURL": verificationURL,
	})
	if err != nil {
		return err
	}

	email := &Email{
		To:      to,
		Subject: "Verify Your Email Address",
		Body:    body,
	}

	return s.Send(email)
}

// SendPasswordReset sends a password reset email
func (s *Service) SendPasswordReset(to, name, resetURL string) error {
	body, err := s.renderTemplate("password_reset.html", map[string]string{
		"Name":     name,
		"ResetURL": resetURL,
	})
	if err != nil {
		return err
	}

	email := &Email{
		To:      to,
		Subject: "Reset Your Password",
		Body:    body,
	}

	return s.Send(email)
}

// renderTemplate renders an email template
func (s *Service) renderTemplate(templateName string, data map[string]string) (string, error) {
	// For development, check if template exists
	path := filepath.Join(s.tmplDir, templateName)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Return a simple HTML template if file doesn't exist
		return s.fallbackTemplate(data), nil
	}

	tmpl, err := template.ParseFiles(path)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// fallbackTemplate provides a simple HTML fallback
func (s *Service) fallbackTemplate(data map[string]string) string {
	name := data["Name"]
	if name == "" {
		name = "there"
	}

	var content string
	if url, ok := data["VerificationURL"]; ok {
		content = fmt.Sprintf(`
			<h2>Verify Your Email Address</h2>
			<p>Hi %s,</p>
			<p>Please click the link below to verify your email address:</p>
			<p><a href="%s">Verify Email</a></p>
			<p>If you didn't request this, please ignore this email.</p>
		`, name, url)
	} else if url, ok := data["ResetURL"]; ok {
		content = fmt.Sprintf(`
			<h2>Reset Your Password</h2>
			<p>Hi %s,</p>
			<p>Please click the link below to reset your password:</p>
			<p><a href="%s">Reset Password</a></p>
			<p>If you didn't request this, please ignore this email.</p>
		`, name, url)
	} else {
		content = fmt.Sprintf(`<p>Hi %s,</p><p>%s</p>`, name, "This is an automated email.")
	}

	return fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="UTF-8">
		<style>
			body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
			h2 { color: #2563eb; }
			a { color: #2563eb; text-decoration: none; }
			a:hover { text-decoration: underline; }
		</style>
	</head>
	<body>
		%s
		<hr>
		<p><small>This is an automated email from %s.</small></p>
	</body>
	</html>
	`, content, s.config.FromName)
}
