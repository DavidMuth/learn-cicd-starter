package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetPIKey(t *testing.T) {
	tests := map[string]struct {
		input http.Header
		want  string
		err   error
	}{
		"no auth header": {
			input: http.Header{
				"Api-Key": []string{"Bearer 123"},
			},
			want: "",
			err:  ErrNoAuthHeaderIncluded,
		},
		"auth header included and is ok": {
			input: http.Header{
				"Authorization": []string{"ApiKey 123"},
			},
			want: "123",
			err:  nil,
		},
		"auth header malformed": {
			input: http.Header{
				"Authorization": []string{"Bearer ApiKey 123"},
			},
			want: "",
			err:  errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, gotErr := GetAPIKey(tc.input)
			if gotErr != nil {
				if tc.err == nil {
					t.Fatalf("for input %v expected output %s and error encountered but error must be nil", tc.input, tc.want)
				} else if gotErr.Error() != tc.err.Error() {
					t.Fatalf("for input %v expected output %s and error encountered:\n\tgot error: %v but error must be: %v", tc.input, tc.want, gotErr, tc.err)
				}
			}
			if !reflect.DeepEqual(tc.want, got) {
				t.Fatalf("expected: %v, got: %v", tc.want, got)
			}
		})
	}

}
