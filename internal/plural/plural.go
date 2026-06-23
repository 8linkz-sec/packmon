package plural

import "fmt"

// Word returns the singular form only for exactly one item.
func Word(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

// Count formats a number with the right singular or plural word.
func Count(count int, singular, pluralWord string) string {
	return fmt.Sprintf("%d %s", count, Word(count, singular, pluralWord))
}
