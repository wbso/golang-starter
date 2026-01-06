package validator

import (
	"testing"
)

func TestValidator_Required(t *testing.T) {
	v := New()
	v.Required("field1", "value")
	if v.HasErrors() {
		t.Errorf("Expected no errors for valid Required, got %v", v.Errors())
	}

	v2 := New()
	v2.Required("field2", "")
	if !v2.HasErrors() {
		t.Error("Expected errors for empty Required field")
	}
	if len(v2.Errors()["field2"]) == 0 {
		t.Error("Expected error message for empty Required field")
	}
}

func TestValidator_MinLength(t *testing.T) {
	v := New()
	v.MinLength("field1", "test123", 6)
	if v.HasErrors() {
		t.Errorf("Expected no errors for valid MinLength, got %v", v.Errors())
	}

	v2 := New()
	v2.MinLength("field2", "test", 6)
	if !v2.HasErrors() {
		t.Error("Expected errors for MinLength validation failure")
	}
}

func TestValidator_MaxLength(t *testing.T) {
	v := New()
	v.MaxLength("field1", "test", 6)
	if v.HasErrors() {
		t.Errorf("Expected no errors for valid MaxLength, got %v", v.Errors())
	}

	v2 := New()
	v2.MaxLength("field2", "test123456", 4)
	if !v2.HasErrors() {
		t.Error("Expected errors for MaxLength validation failure")
	}
}

func TestValidator_Email(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		wantError bool
	}{
		{"valid email", "test@example.com", false},
		{"invalid email", "invalid", true},
		{"empty email", "", false}, // empty should not error
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.Email("email", tt.email)
			if tt.wantError && !v.HasErrors() {
				t.Errorf("Expected error for email %s", tt.email)
			}
			if !tt.wantError && v.HasErrors() {
				t.Errorf("Expected no error for email %s, got %v", tt.email, v.Errors())
			}
		})
	}
}

func TestValidator_Password(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantError bool
	}{
		{"valid password", "Test1234", false},
		{"too short", "Test1", true},
		{"no uppercase", "test1234", true},
		{"no lowercase", "TEST1234", true},
		{"no digit", "Testtest", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.Password("password", tt.password)
			if tt.wantError && !v.HasErrors() {
				t.Errorf("Expected error for password %s", tt.password)
			}
			if !tt.wantError && v.HasErrors() {
				t.Errorf("Expected no error for password %s, got %v", tt.password, v.Errors())
			}
		})
	}
}

func TestValidator_Username(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		wantError bool
	}{
		{"valid username", "user123", false},
		{"valid with underscore", "user_123", false},
		{"invalid with dash", "user-123", true},
		{"invalid with space", "user 123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.Username("username", tt.username)
			if tt.wantError && !v.HasErrors() {
				t.Errorf("Expected error for username %s", tt.username)
			}
			if !tt.wantError && v.HasErrors() {
				t.Errorf("Expected no error for username %s, got %v", tt.username, v.Errors())
			}
		})
	}
}

func TestValidator_Match(t *testing.T) {
	v := New()
	v.Match("password", "confirm", "password123", "password123")
	if v.HasErrors() {
		t.Errorf("Expected no errors for matching fields, got %v", v.Errors())
	}

	v2 := New()
	v2.Match("password", "confirm", "password123", "different123")
	if !v2.HasErrors() {
		t.Error("Expected errors for non-matching fields")
	}
}

func TestValidator_Custom(t *testing.T) {
	v := New()
	v.Custom("field1", "custom error message")
	if !v.HasErrors() {
		t.Error("Expected errors for Custom validation")
	}
	if v.Errors()["field1"][0] != "custom error message" {
		t.Errorf("Expected custom error message, got %v", v.Errors()["field1"])
	}
}

func TestPasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		minScore int
	}{
		{"weak password", "test", 0},
		{"fair password", "Test12345", 1},
		{"good password", "Test123456", 2},
		{"strong password", "Test1234!@#", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := PasswordStrength(tt.password)
			if score < tt.minScore {
				t.Errorf("PasswordStrength(%s) = %d, want >= %d", tt.password, score, tt.minScore)
			}
		})
	}
}
