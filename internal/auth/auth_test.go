package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	cases := []struct {
		name          string
		input         http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "no header provided",
			input:         http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - wrong prefix",
			input: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer sometoken")
				return h
			}(),
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "valid header",
			input: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey my-secret-key")
				return h
			}(),
			expectedKey:   "my-secret-key",
			expectedError: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := GetAPIKey(c.input)

			if key != c.expectedKey {
				t.Errorf("expected %q, got %q", c.expectedKey, key)
			}

			if (err == nil && c.expectedError != nil) ||
				(err != nil && c.expectedError == nil) ||
				(err != nil && c.expectedError != nil && err.Error() != c.expectedError.Error()) {
				t.Errorf("expected %v, got %v", c.expectedError, err)
			}
		})

	}
}
