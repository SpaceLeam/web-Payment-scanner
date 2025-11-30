package utils

import (
	"fmt"
	"log"
	"os"
	"time"
	
	"github.com/fatih/color"
)

// Logger levels
const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelCritical
)

// Logger handles formatted logging output
type Logger struct {
	level   int
	verbose bool
}

// NewLogger creates a new logger instance
func NewLogger(verbose bool) *Logger {
	return &Logger{
		level:   LevelInfo,
		verbose: verbose,
	}
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level int) {
	l.level = level
}

// Debug logs debug messages (only in verbose mode)
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.verbose && l.level <= LevelDebug {
		msg := fmt.Sprintf(format, args...)
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("[%s] %s %s\n", timestamp, color.CyanString("DEBUG"), msg)
	}
}

// Info logs informational messages
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level <= LevelInfo {
		msg := fmt.Sprintf(format, args...)
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("[%s] %s %s\n", timestamp, color.BlueString("INFO"), msg)
	}
}

// Success logs success messages (special case of Info)
func (l *Logger) Success(format string, args ...interface{}) {
	if l.level <= LevelInfo {
		msg := fmt.Sprintf(format, args...)
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("[%s] %s %s\n", timestamp, color.GreenString("✓"), msg)
	}
}

// Warn logs warning messages
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level <= LevelWarn {
		msg := fmt.Sprintf(format, args...)
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("[%s] %s %s\n", timestamp, color.YellowString("WARN"), msg)
	}
}

// Error logs error messages
func (l *Logger) Error(format string, args ...interface{}) {
	if l.level <= LevelError {
		msg := fmt.Sprintf(format, args...)
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("[%s] %s %s\n", timestamp, color.RedString("ERROR"), msg)
	}
}

// Critical logs critical errors and exits
func (l *Logger) Critical(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("[%s] %s %s\n", timestamp, color.RedString("CRITICAL"), msg)
	os.Exit(1)
}

// Fatal logs a fatal error and exits
func (l *Logger) Fatal(err error) {
	if err != nil {
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("[%s] %s %s\n", timestamp, color.RedString("FATAL"), err.Error())
		os.Exit(1)
	}
}

// Banner prints a formatted banner
func (l *Logger) Banner(text string) {
	fmt.Println()
	fmt.Println(color.CyanString("═══════════════════════════════════════════════════════════"))
	fmt.Println(color.CyanString("  " + text))
	fmt.Println(color.CyanString("═══════════════════════════════════════════════════════════"))
	fmt.Println()
}

// Section prints a section header
func (l *Logger) Section(text string) {
	fmt.Println()
	fmt.Println(color.YellowString("▶ " + text))
	fmt.Println(color.YellowString("───────────────────────────────────────────────────────────"))
}

// Helper function for standard logging (backward compatible)
func LogInfo(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func LogError(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func LogDebug(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format, args...)
}
