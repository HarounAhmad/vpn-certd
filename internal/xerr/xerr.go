package xerr

import "fmt"

type Code string

const (
	BadRequest Code = "bad_request"
	Forbidden  Code = "forbidden"
	NotFound   Code = "not_found"
	Conflict   Code = "conflict"
	Internal   Code = "internal_error"
	NotImpl    Code = "not_implemented"
)

type E struct {
	Code Code
	Msg  string
}

func (e E) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Msg) }

func Bad(msg string) error            { return E{Code: BadRequest, Msg: msg} }
func InternalErr(msg string) error    { return E{Code: Internal, Msg: msg} }
func NotImplemented(msg string) error { return E{Code: NotImpl, Msg: msg} }
func ConflictErr(msg string) error    { return E{Code: Conflict, Msg: msg} }
