package captcha

import "errors"

const (
	CapErrZeroBalance          = "ERROR_ZERO_BALANCE"
	CapErrTypeNotSupported     = "ERROR_TYPE_NOT_SUPPORTED"
	CapErrTaskNotFound         = "ERROR_TASK_NOT_FOUND"
	CapErrTaskAborted          = "ERROR_TASK_ABORTED"
	CapErrTaskCanceled         = "ERROR_TASK_CANCELED"
	CapErrInvalidRequestData   = "invalid request data"
	CapErrInvalidTaskData      = "invalid task data"
	CapErrMaxRequestsPerMinute = "max requests per minute"
	CapErrMaxConcurrentTasks   = "max concurrent tasks"
)

const (
	TwoErrZeroBalance       = "ERROR_ZERO_BALANCE"
	TwoErrNoSlots           = "ERROR_NO_SLOT_AVAILABLE"
	TwoErrCaptchaUnsolvable = "ERROR_CAPTCHA_UNSOLVABLE"
	TwoErrBadTokenOrNull    = "ERROR_BAD_TOKEN_OR_NULL"
	TwoErrTokenExpired      = "ERROR_TOKEN_EXPIRED"
	TwoErrReportNotRecorded = "ERROR_REPORT_NOT_RECORDED"
	TwoErrRecaptcha2Failed  = "ERROR_RECAPTCHA_UNSOLVABLE"
	TwoErrLimitReached      = "ERROR_LIMIT_REACHED"
)

var ErrZeroBalance = errors.New("captcha solver zero balance")
