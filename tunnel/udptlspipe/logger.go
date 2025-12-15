/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 AmneziaWG. All Rights Reserved.
 */

package udptlspipe

import (
	"fmt"
	"log"
)

// Logger is a simple logger interface used by udptlspipe
type Logger interface {
	Printf(format string, args ...interface{})
}

// DefaultLogger wraps the standard log package
type DefaultLogger struct{}

func (l *DefaultLogger) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

// NopLogger is a logger that does nothing
type NopLogger struct{}

func (l *NopLogger) Printf(format string, args ...interface{}) {}

// PrefixLogger wraps another logger with a prefix
type PrefixLogger struct {
	Prefix string
	Logger Logger
}

func (l *PrefixLogger) Printf(format string, args ...interface{}) {
	l.Logger.Printf(l.Prefix+format, args...)
}

// FuncLogger adapts a Printf-style function to the Logger interface
type FuncLogger func(format string, args ...interface{})

func (f FuncLogger) Printf(format string, args ...interface{}) {
	f(format, args...)
}

// NewFuncLogger creates a Logger from a printf-style function
func NewFuncLogger(fn func(format string, args ...interface{})) Logger {
	return FuncLogger(fn)
}

// StdLogger adapts the standard library log.Logger to our Logger interface
type StdLogger struct {
	*log.Logger
}

func (l *StdLogger) Printf(format string, args ...interface{}) {
	l.Logger.Printf(format, args...)
}

// NewStdLogger creates a Logger from a standard library log.Logger
func NewStdLogger(logger *log.Logger) Logger {
	if logger == nil {
		logger = log.Default()
	}
	return &StdLogger{Logger: logger}
}

// Version returns the udptlspipe version
func Version() string {
	return "1.3.1"
}

// Error handling for debugging
var lastError string

func setLastError(err error) {
	if err != nil {
		lastError = err.Error()
	} else {
		lastError = ""
	}
}

func getLastError() string {
	return lastError
}

// GetLastError returns the last error message, if any
func GetLastError() string {
	return getLastError()
}

// ClearLastError clears the last error message
func ClearLastError() {
	setLastError(nil)
}

// FormatError returns a formatted error string
func FormatError(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("udptlspipe: %v", err)
}
