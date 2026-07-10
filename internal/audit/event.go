package audit

import (
	"time"

	"captcha/internal/types"
)

func SanitizeReportedEvent(event types.AuditEvent) types.AuditEvent {
	event.ID = ""
	event.CreatedAt = time.Time{}
	return event
}
