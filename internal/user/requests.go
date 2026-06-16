package user

type CreateUserRequest struct {
	FirstName string
	LastName  string
	Email     string
	Username  string
	Password  string
}

type UpdateUserNameRequest struct {
	FirstName string
	LastName  string
}

type UpdateUserEmailRequest struct {
	Email string
}

type UpdateUserPasswordRequest struct {
	CurrentPassword string
	NewPassword     string
}

type UpdateUserUsernameRequest struct {
	Username string
}
