package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
		{
			name:    "missing authorization header",
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "wrong scheme",
			headers: http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "scheme without key",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}

			switch {
			case tt.wantErr == nil && gotErr != nil:
				t.Errorf("GetAPIKey() unexpected error: %v", gotErr)
			case tt.wantErr != nil && gotErr == nil:
				t.Errorf("GetAPIKey() expected error %q, got nil", tt.wantErr)
			case tt.wantErr != nil && gotErr != nil:
				if !errors.Is(gotErr, tt.wantErr) && gotErr.Error() != tt.wantErr.Error() {
					t.Errorf("GetAPIKey() error = %q, want %q", gotErr, tt.wantErr)
				}
			}
		})
	}
}
