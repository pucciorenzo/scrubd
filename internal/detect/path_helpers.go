package detect

import "strings"

func pathSegments(path string) []string {
	parts := strings.Split(strings.ToLower(path), "/")
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			segments = append(segments, part)
		}
	}
	return segments
}

func pathHasSegment(path, segment string) bool {
	segment = strings.ToLower(segment)
	for _, item := range pathSegments(path) {
		if item == segment {
			return true
		}
	}
	return false
}

func pathHasSegmentPrefix(path, prefix string) bool {
	prefix = strings.ToLower(prefix)
	for _, item := range pathSegments(path) {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}

func pathLastSegment(path string) string {
	segments := pathSegments(path)
	if len(segments) == 0 {
		return ""
	}
	return segments[len(segments)-1]
}

func pathHasPrefixBoundary(path, prefix string) bool {
	path = strings.TrimRight(strings.ToLower(strings.TrimSpace(path)), "/")
	prefix = strings.TrimRight(strings.ToLower(strings.TrimSpace(prefix)), "/")
	if path == "" || prefix == "" {
		return false
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}
