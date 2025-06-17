package logutil

import (
	"log"
)

var DebugEnabled bool

func DebugLog(format string, args ...any) {
	if DebugEnabled {
		log.Printf("[NextPKI debug] "+format, args...)
	}
}

func ErrorLog(format string, args ...any) {
	log.Printf("[NextPKI error] "+format, args...)
}
