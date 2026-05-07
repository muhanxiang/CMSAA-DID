package logger

import (
	"fmt"
	"time"
)

// ANSI 转义字符，用于控制台美化输出
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
)

func log(prefix, color, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05.000")
	fmt.Printf("%s[%s] %s%s %s\n", color, timestamp, prefix, colorReset, msg)
}

// Info 输出常规信息
func Info(format string, args ...interface{}) {
	log("INFO", colorBlue, format, args...)
}

// Step 输出阶段性推进信息
func Step(format string, args ...interface{}) {
	log("STEP", colorCyan, format, args...)
}

// Success 输出成功结果
func Success(format string, args ...interface{}) {
	log("SUCCESS", colorGreen, format, args...)
}

// Warn 输出警告信息
func Warn(format string, args ...interface{}) {
	log("WARN", colorYellow, format, args...)
}

// Error 输出错误信息
func Error(format string, args ...interface{}) {
	log("ERROR", colorRed, format, args...)
}
