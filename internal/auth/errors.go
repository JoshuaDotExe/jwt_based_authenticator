package auth

import "errors"

var ErrMissingCredentials = errors.New("username and password are required")
var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidTokenInput = errors.New("sub is required")
