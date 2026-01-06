package apperrors

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
)

// CustomHTTPErrorHandler is the default HTTP Error Handler
func CustomHTTPErrorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}

	var appErr *AppError
	if errors.As(err, &appErr) {
		_ = c.JSON(appErr.Code, appErr)
		return
	}

	var he *echo.HTTPError
	if errors.As(err, &he) {
		if he.Internal != nil {
			var herr *echo.HTTPError
			if errors.As(he.Internal, &herr) {
				he = herr
			}
		}
	} else {
		he = &echo.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
		}
	}

	// Issue #1426
	code := he.Code
	message := he.Message

	switch m := he.Message.(type) {
	case string:
		if c.Echo().Debug {
			message = echo.Map{"message": m, "error": err.Error()}
		} else {
			message = echo.Map{"message": m}
		}
	case json.Marshaler:
		// do nothing - this type knows how to format itself to JSON
	case error:
		message = echo.Map{"message": m.Error()}
	}

	// Send response
	if c.Request().Method == http.MethodHead { // Issue #608
		err = c.NoContent(he.Code)
	} else {
		err = c.JSON(code, message)
	}
	if err != nil {
		c.Logger().Error(err)
	}

	// if c.Response().Committed {
	// 	return
	// }

	// c.Logger().Error(err)

	// code := http.StatusInternalServerError
	// var he *echo.HTTPError
	// if errors.As(err, &he) {
	// 	code = he.Code
	// 	c.JSON(code, he)
	// 	return
	// }

	// c.JSON(code, &AppError{
	// 	Code:   code,
	// 	Title:  http.StatusText(code),
	// 	Detail: err.Error(),
	// 	Err:    err,
	// 	Type:   getErrorType(code),
	// 	Errors: nil,
	// })

	// c.String(http.StatusInternalServerError, err.Error())
}
