package validator

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"unicode"
)

// Validator provides validation functions
type Validator struct {
	errors map[string][]string
}

// New creates a new validator
func New() *Validator {
	return &Validator{
		errors: make(map[string][]string),
	}
}

// Required checks if a string field is not empty
func (v *Validator) Required(field, value string) *Validator {
	if value == "" {
		v.errors[field] = append(v.errors[field], fmt.Sprintf("%s is required", field))
	}
	return v
}

// MinLength checks if a string field meets minimum length
func (v *Validator) MinLength(field, value string, min int) *Validator {
	if len(value) < min {
		v.errors[field] = append(v.errors[field], fmt.Sprintf("%s must be at least %d characters", field, min))
	}
	return v
}

// MaxLength checks if a string field doesn't exceed maximum length
func (v *Validator) MaxLength(field, value string, max int) *Validator {
	if len(value) > max {
		v.errors[field] = append(v.errors[field], fmt.Sprintf("%s must be at most %d characters", field, max))
	}
	return v
}

// Email checks if a string is a valid email
func (v *Validator) Email(field, value string) *Validator {
	if value == "" {
		return v
	}
	if _, err := mail.ParseAddress(value); err != nil {
		v.errors[field] = append(v.errors[field], fmt.Sprintf("%s must be a valid email", field))
	}
	return v
}

// Password checks if a password meets requirements
// Minimum 8 characters, at least one uppercase, one lowercase, one digit
func (v *Validator) Password(field, value string) *Validator {
	if len(value) < 8 {
		v.errors[field] = append(v.errors[field], "password must be at least 8 characters")
		return v
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range value {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		v.errors[field] = append(v.errors[field], "password must contain at least one uppercase letter")
	}
	if !hasLower {
		v.errors[field] = append(v.errors[field], "password must contain at least one lowercase letter")
	}
	if !hasDigit {
		v.errors[field] = append(v.errors[field], "password must contain at least one digit")
	}
	// Special character is optional but recommended
	_ = hasSpecial // Keep the variable but don't enforce it

	return v
}

// Username checks if a username is valid (alphanumeric and underscore only)
func (v *Validator) Username(field, value string) *Validator {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_]+$`, value)
	if !matched {
		v.errors[field] = append(v.errors[field], "username can only contain letters, numbers, and underscores")
	}
	return v
}

// Match checks if two fields match (e.g., password confirmation)
func (v *Validator) Match(field1, field2, value1, value2 string) *Validator {
	if value1 != value2 {
		v.errors[field1] = append(v.errors[field1], fmt.Sprintf("%s does not match %s", field1, field2))
	}
	return v
}

// Custom adds a custom validation error
func (v *Validator) Custom(field, message string) *Validator {
	v.errors[field] = append(v.errors[field], message)
	return v
}

// HasErrors returns true if there are validation errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// Errors returns the validation errors
func (v *Validator) Errors() map[string][]string {
	return v.errors
}

// Error returns the validation error
func (v *Validator) Error() error {
	if !v.HasErrors() {
		return nil
	}
	return errors.New("validation failed")
}

// Clear clears all validation errors
func (v *Validator) Clear() {
	v.errors = make(map[string][]string)
}

// PasswordStrength checks password strength and returns a score
// Returns: 0 (weak), 1 (fair), 2 (good), 3 (strong)
func PasswordStrength(password string) int {
	if len(password) < 8 {
		return 0
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	strength := 0
	if hasUpper && hasLower {
		strength++
	}
	if hasDigit {
		strength++
	}
	if hasSpecial {
		strength++
	}
	if len(password) >= 12 {
		strength++
	}

	return strength
}
