package models

import "strings"

const (
	ErrNotFound          modelError = "models: resource not found"
	ErrPasswordIncorrect modelError = "models: incorrect password provided"
	ErrEmailRequired     modelError = "models: email address is required"
	ErrEmailInvalid      modelError = "models: email address is not valid"
	ErrEmailTaken        modelError = "model: email address is already taken"
	ErrPasswordTooShort  modelError = "models: password must be at least 8 chars"
	ErrPasswordRequired  modelError = "models: password is required"
	ErrTitleRequired     modelError = "models: title is required"

	ErrRememberTooShort privateError = "models: remember token must be at least 32 bytes"
	ErrRememberRequired privateError = "models: remember token is required"
	ErrUserIDRequired   privateError = "models: user ID is required"
	ErrIDInvalid        privateError = "models: ID must be > 0"
)

type modelError string

func (e modelError) Error() string {
	return string(e)
}

func (e modelError) Public() string {
	s := strings.Replace(string(e), "models: ", "", 1)
	return strings.Title(s)
}

type privateError string

func (e privateError) Error() string {
	return string(e)
}
