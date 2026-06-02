## Refresh Token

## ID Token

## Access Token Structure Reference

This document describes the access token claim structure used by this project.

The access token has the following claims with a 15 minute token lifetime.

### Access Token Payload Example

```json
{
	"iss": "auth.local",
	"sub": "2c6f6b1e-c978-49dc-9f9c-e58f807cb229",
	"aud": "api.local",
	"iat": 1717322400,
	"exp": 1717323300,
	"jti": "7de0faec-f0ea-4fd4-b881-99d0dc3402bc"
}
```
