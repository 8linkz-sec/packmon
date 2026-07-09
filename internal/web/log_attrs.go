package web

import (
	"context"
	"net/http"

	"github.com/8linkz-sec/packmon/internal/requestctx"
)

func requestLogAttrs(r *http.Request, attrs ...any) []any {
	return contextLogAttrs(r.Context(), attrs...)
}

func contextLogAttrs(ctx context.Context, attrs ...any) []any {
	correlationID := requestctx.CorrelationIDFromContext(ctx)
	if correlationID == "" {
		return attrs
	}
	withCorrelation := make([]any, 0, len(attrs)+2)
	withCorrelation = append(withCorrelation, attrs...)
	withCorrelation = append(withCorrelation, "correlation_id", correlationID)
	return withCorrelation
}
