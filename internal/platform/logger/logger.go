package logger

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ohmynofan/blockstreet-testnet-bot/internal/domain/model"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/platform/ui"
	"github.com/ohmynofan/blockstreet-testnet-bot/pkg/utils"
)

var (
	fileLogger *log.Logger
	once       sync.Once
	logFile    *os.File
)

func Init(path string) error {
	var err error
	once.Do(func() {
		os.Remove(path)
		if err = os.MkdirAll(dirOf(path), 0o755); err != nil {
			return
		}
		logFile, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		fileLogger = log.New(logFile, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	})
	return err
}

func Close() error {
	if logFile != nil {
		return logFile.Close()
	}
	return nil
}

func dirOf(path string) string {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "."
	}
	return path[:i]
}

type ClassLogger struct {
	class   string
	session *model.Session
}

func NewLogger(v interface{}, session *model.Session) *ClassLogger {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return &ClassLogger{class: t.Name(), session: normalizeSession(session)}
}

func NewNamed(name string, session *model.Session) *ClassLogger {
	return &ClassLogger{class: name, session: normalizeSession(session)}
}

func normalizeSession(session *model.Session) *model.Session {
	if session == nil {
		return nil
	}
	return session.LoggingSession()
}

func (l *ClassLogger) Log(msg string, durationMs ...int) {
	totalDuration := 300 * time.Millisecond
	if len(durationMs) > 0 {
		totalDuration = time.Duration(durationMs[0]) * time.Millisecond
	}

	session := l.session
	if session == nil {
		return
	}

	if fileLogger != nil {
		funcName := callerFunc(2)
		label := fmt.Sprintf("Operation - Account %d", session.AccIdx+1)
		fileLogger.Printf("[%s][%s] %s", label, funcName, msg)
	}

	displayMsg := shortenForDisplay(msg)

	if totalDuration > 0 {
		interval := 1 * time.Second

		for remaining := totalDuration; remaining > 0; remaining -= interval {
			ui.UpdateStatus(*session, displayMsg, remaining)

			sleepTime := interval
			if remaining < interval {
				sleepTime = remaining
			}
			time.Sleep(sleepTime)
		}
	}

	ui.UpdateStatus(*session, displayMsg, 0)
}

func (l *ClassLogger) JustLog(msg string) {
	session := l.session
	if fileLogger != nil {
		funcName := callerFunc(2)
		if session != nil {
			label := fmt.Sprintf("Operation - Account %d", session.AccIdx+1)
			fileLogger.Printf("[%s][%s] %s", label, funcName, msg)
		} else {
			fileLogger.Printf("[%s][%s] %s", l.class, funcName, msg)
		}
	}
}

func (l *ClassLogger) LogObject(msg string, obj interface{}) {
	if fileLogger != nil {
		formattedString, err := utils.FormatObject(obj)
		if err != nil {
			l.JustLog(fmt.Sprintf("Error formatting object: %v", err))
			return
		}
		l.JustLog(fmt.Sprintf("%s : \n%v", msg, formattedString))
	}
}

func callerFunc(skip int) string {
	pc, _, _, ok := runtime.Caller(skip)
	if !ok {
		return "unknown"
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unknown"
	}
	parts := strings.Split(fn.Name(), ".")
	return parts[len(parts)-1]
}

func shortenForDisplay(msg string) string {
	const maxLen = 140
	runes := []rune(msg)
	if len(runes) <= maxLen {
		return msg
	}
	return string(runes[:maxLen-1]) + "…"
}
