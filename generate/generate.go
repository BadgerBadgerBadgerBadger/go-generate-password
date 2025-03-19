// Package generate is a Go port of the npm package generate-password (https://www.npmjs.com/package/generate-password).
// It provides functionality to generate secure random passwords with various options for customization.
//
// Examples:
//
//	// Generate a basic password
//	pg := generate.NewPasswordGenerator()
//	opts := generate.PasswordOptions{
//	    Length:    12,
//	    Lowercase: true,
//	    Uppercase: true,
//	}
//	password, err := pg.Generate(opts)
//	if err != nil {
//	    log.Fatalf("Error generating password: %v", err)
//	}
//	fmt.Println(password)
//
//	// Generate a more complex password
//	complexOpts := generate.PasswordOptions{
//	    Length:                   16,
//	    Lowercase:                true,
//	    Uppercase:                true,
//	    Numbers:                  true,
//	    Symbols:                  true,
//	    ExcludeSimilarCharacters: true,
//	    Strict:                   true,
//	}
//	complexPassword, err := pg.Generate(complexOpts)
//	if err != nil {
//	    log.Fatalf("Error generating password: %v", err)
//	}
//	fmt.Println(complexPassword)
//
//	// Generate multiple passwords
//	passwords, err := pg.GenerateMultiple(5, opts)
//	if err != nil {
//	    log.Fatalf("Error generating passwords: %v", err)
//	}
//	for _, pass := range passwords {
//	    fmt.Println(pass)
//	}
package generate

import (
	"crypto/rand"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

// PasswordGenerator holds the state for generating passwords.
type PasswordGenerator struct {
	randomIndex int
	randomBytes []byte
}

// PasswordOptions defines the options for password generation.
type PasswordOptions struct {
	// Length specifies the number of characters the generated password should contain.
	Length int

	// Numbers specifies whether the generated password should include numbers.
	Numbers bool

	// Symbols specifies whether the generated password should include symbols.
	Symbols bool

	// Exclude specifies characters that should be excluded from the generated password.
	Exclude string

	// Uppercase specifies whether the generated password should include uppercase letters.
	Uppercase bool

	// Lowercase specifies whether the generated password should include lowercase letters.
	Lowercase bool

	// ExcludeSimilarCharacters specifies whether the password should exclude similar characters
	// such as 'i', 'l', '1', 'L', 'o', '0', 'O', etc.
	ExcludeSimilarCharacters bool

	// Strict enforces that the password must include at least one character from each selected character pool.
	// For example, if Lowercase, Uppercase, and Numbers are all true, then the password must include
	// at least one lowercase letter, one uppercase letter, and one number.
	Strict bool

	// SymbolsString allows specifying a custom set of symbols to use instead of the default symbol set.
	// This is only used if Symbols is set to true.
	SymbolsString string
}

// Define character pools.
const (
	lowercase = "abcdefghijklmnopqrstuvwxyz"
	uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers   = "0123456789"
	symbols   = "!@#$%^&*()+_-=}{[]|:;\"/?.><,`~"
)

// similarCharactersRegex defines characters that look similar.
var similarCharactersRegex = regexp.MustCompile("[ilLI|`oO0]")

// strictRule defines a rule for strict password generation.
type strictRule struct {
	name string
	rule *regexp.Regexp
}

// strictRules defines the rules for strict password generation.
var strictRules = []strictRule{
	{name: "lowercase", rule: regexp.MustCompile(`[a-z]`)},
	{name: "uppercase", rule: regexp.MustCompile(`[A-Z]`)},
	{name: "numbers", rule: regexp.MustCompile(`[0-9]`)},
	{name: "symbols", rule: regexp.MustCompile(`[!@#$%^&*()+_\-=}{[\]|:;"/?.,><` + "`" + `~]`)},
}

// NewPasswordGenerator creates a new password generator.
func NewPasswordGenerator() *PasswordGenerator {
	return &PasswordGenerator{}
}

// getNextRandomValue gets the next random byte from the buffer.
func (pg *PasswordGenerator) getNextRandomValue() (byte, error) {
	if pg.randomIndex == 0 || pg.randomIndex >= len(pg.randomBytes) {
		pg.randomIndex = 0
		pg.randomBytes = make([]byte, 256) // Same as RANDOM_BATCH_SIZE in JS.
		_, err := rand.Read(pg.randomBytes)
		if err != nil {
			return 0, errors.Wrap(err, "failed to generate random bytes")
		}
	}

	result := pg.randomBytes[pg.randomIndex]
	pg.randomIndex++

	return result, nil
}

// randomNumber generates a random number between 0 (inclusive) and max (exclusive).
func (pg *PasswordGenerator) randomNumber(max int) (int, error) {
	rndVal, err := pg.getNextRandomValue()
	if err != nil {
		return 0, errors.Wrap(err, "failed to get random value")
	}

	// This is to ensure unbiased random numbers, equivalent to the JS version.
	// Work with int types for the calculation to avoid byte overflow.
	limit := 256 - (256 % max)
	for int(rndVal) >= limit {
		rndVal, err = pg.getNextRandomValue()
		if err != nil {
			return 0, errors.Wrap(err, "failed to get random value")
		}
	}

	return int(rndVal) % max, nil
}

// Generate generates a password according to the specified options.
func (pg *PasswordGenerator) Generate(options PasswordOptions) (string, error) {
	// Validate options.
	if options.Strict {
		minStrictLength := 0
		if options.Lowercase {
			minStrictLength++
		}
		if options.Uppercase {
			minStrictLength++
		}
		if options.Numbers {
			minStrictLength++
		}
		if options.Symbols {
			minStrictLength++
		}

		if minStrictLength > options.Length {
			return "", errors.New("length must correlate with strict guidelines")
		}
	}

	// Generate character pool.
	var pool strings.Builder

	if options.Lowercase {
		pool.WriteString(lowercase)
	}

	if options.Uppercase {
		pool.WriteString(uppercase)
	}

	if options.Numbers {
		pool.WriteString(numbers)
	}

	if options.Symbols {
		if options.SymbolsString != "" {
			pool.WriteString(options.SymbolsString)
		} else {
			pool.WriteString(symbols)
		}
	}

	if pool.Len() == 0 {
		return "", errors.New("at least one rule for pools must be true")
	}

	poolStr := pool.String()

	// Exclude similar characters.
	if options.ExcludeSimilarCharacters {
		poolStr = similarCharactersRegex.ReplaceAllString(poolStr, "")
	}

	// Exclude specified characters.
	for _, char := range options.Exclude {
		poolStr = strings.ReplaceAll(poolStr, string(char), "")
	}

	// Generate password.
	password, err := pg.generateInternal(options, poolStr)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate password")
	}

	return password, nil
}

// generateInternal is the internal function that generates a password.
func (pg *PasswordGenerator) generateInternal(options PasswordOptions, pool string) (string, error) {
	var password strings.Builder
	poolLength := len(pool)

	for i := 0; i < options.Length; i++ {
		randIndex, err := pg.randomNumber(poolLength)
		if err != nil {
			return "", errors.Wrap(err, "failed to generate random number")
		}

		password.WriteByte(pool[randIndex])
	}

	if options.Strict {
		// Check if password meets all required rules.
		allRulesMet := true
		for _, rule := range strictRules {
			// Skip rule if corresponding option is false.
			switch rule.name {
			case "lowercase":
				if !options.Lowercase {
					continue
				}
			case "uppercase":
				if !options.Uppercase {
					continue
				}
			case "numbers":
				if !options.Numbers {
					continue
				}
			case "symbols":
				if !options.Symbols {
					continue
				}

				// Handle custom symbols.
				if options.SymbolsString != "" {
					customSymbolsRegex := regexp.MustCompile("[" + regexp.QuoteMeta(options.SymbolsString) + "]")
					if !customSymbolsRegex.MatchString(password.String()) {
						allRulesMet = false
						break
					}
					continue
				}
			}

			if !rule.rule.MatchString(password.String()) {
				allRulesMet = false
				break
			}
		}

		// If not all rules are met, generate a new password.
		if !allRulesMet {
			return pg.generateInternal(options, pool)
		}
	}

	return password.String(), nil
}

// GenerateMultiple generates multiple passwords with the same options.
func (pg *PasswordGenerator) GenerateMultiple(amount int, options PasswordOptions) ([]string, error) {
	passwords := make([]string, amount)

	for i := 0; i < amount; i++ {
		password, err := pg.Generate(options)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate password")
		}
		passwords[i] = password
	}

	return passwords, nil
}
