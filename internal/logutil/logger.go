package logutil

import (
	"log"
)

var DebugEnabled bool

func DebugLog(format string, args ...any) {
	if DebugEnabled {
		log.Printf("[UltraPKI debug] "+format, args...)
	}
}

func ErrorLog(format string, args ...any) {
	log.Printf("[UltraPKI error] "+format, args...)
}
