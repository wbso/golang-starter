package user

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUser_IsLocked(t *testing.T) {
	tests := []struct {
		name        string
		lockedUntil *time.Time
		want        bool
	}{
		{
			name:        "not locked",
			lockedUntil: nil,
			want:        false,
		},
		{
			name:        "locked in past",
			lockedUntil: timePtr(time.Now().Add(-1 * time.Hour)),
			want:        false,
		},
		{
			name:        "locked in future",
			lockedUntil: timePtr(time.Now().Add(1 * time.Hour)),
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{
				LockedUntil: tt.lockedUntil,
			}
			if got := u.IsLocked(); got != tt.want {
				t.Errorf("User.IsLocked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_CanLogin(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name            string
		isDisabled      bool
		isEmailVerified bool
		lockedUntil     *time.Time
		want            bool
	}{
		{
			name:            "can login - all valid",
			isDisabled:      false,
			isEmailVerified: true,
			lockedUntil:     nil,
			want:            true,
		},
		{
			name:            "cannot login - disabled",
			isDisabled:      true,
			isEmailVerified: true,
			lockedUntil:     nil,
			want:            false,
		},
		{
			name:            "cannot login - email not verified",
			isDisabled:      false,
			isEmailVerified: false,
			lockedUntil:     nil,
			want:            false,
		},
		{
			name:            "cannot login - locked",
			isDisabled:      false,
			isEmailVerified: true,
			lockedUntil:     timePtr(now.Add(1 * time.Hour)),
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{
				IsDisabled:      tt.isDisabled,
				IsEmailVerified: tt.isEmailVerified,
				LockedUntil:     tt.lockedUntil,
			}
			if got := u.CanLogin(); got != tt.want {
				t.Errorf("User.CanLogin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_ToResponse(t *testing.T) {
	id := uuid.New()
	fullName := "John Doe"
	now := time.Now()

	u := &User{
		ID:              id,
		Username:        "johndoe",
		Email:           "john@example.com",
		FullName:        &fullName,
		IsDisabled:      false,
		IsEmailVerified: true,
		LastLoginAt:     &now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	resp := u.ToResponse()

	if resp.ID != id {
		t.Errorf("ToResponse() ID = %v, want %v", resp.ID, id)
	}
	if resp.Username != "johndoe" {
		t.Errorf("ToResponse() Username = %v, want %v", resp.Username, "johndoe")
	}
	if resp.Email != "john@example.com" {
		t.Errorf("ToResponse() Email = %v, want %v", resp.Email, "john@example.com")
	}
	if resp.FullName == nil || *resp.FullName != fullName {
		t.Errorf("ToResponse() FullName = %v, want %v", resp.FullName, &fullName)
	}
	if resp.IsDisabled {
		t.Error("ToResponse() IsDisabled = true, want false")
	}
	if !resp.IsEmailVerified {
		t.Error("ToResponse() IsEmailVerified = false, want true")
	}
}

// Helper function
func timePtr(t time.Time) *time.Time {
	return &t
}
