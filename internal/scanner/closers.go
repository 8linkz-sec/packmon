package scanner

import "github.com/8linkz-sec/packmon/internal/ioutils"

// closeSilently is a package-level alias for the shared ioutils.CloseSilently
// helper, kept so that existing call sites remain unchanged.
func closeSilently(c any) {
	ioutils.CloseSilently(c)
}
