package logger

import (
	"fmt"
	"github.com/fatih/color"
	"os"
	"time"
)

const timeFormat = "02-01-2006 15:04:05"

var (
	red    = color.New(color.FgRed)
	green  = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
	cyan   = color.New(color.FgCyan)
)

func CommandSuccess(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(green.Sprintf("%s\n", message))
}

func CommandInfo(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(cyan.Sprintf("%s\n", message))
}

func CommandError(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	_, err := fmt.Fprintf(os.Stderr, red.Sprintf("%s\n", message))
	if err != nil {
		fmt.Printf("Error writing to stderr: %v\n", err)
	}
	os.Exit(1)
}

func CommandWarning(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(yellow.Sprintf("%s\n", message))
}

func Success(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(green.Sprintf("[%s] %s\n", time.Now().Format(timeFormat), message))
}

func Error(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(red.Sprintf("[%s] %s \n", time.Now().Format(timeFormat), message))
}

func Warning(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(yellow.Sprintf("[%s] %s \n", time.Now().Format(timeFormat), message))
}

func Info(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(cyan.Sprintf("[%s] %s \n", time.Now().Format(timeFormat), message))
}

func Fatal(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(red.Sprintf("[%s] %s \n", time.Now().Format(timeFormat), message))
	os.Exit(1)
}
