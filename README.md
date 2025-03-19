# Go-Generate-Password 

This is a Go port of the npm package generate-password (https://www.npmjs.com/package/generate-password).
It provides functionality to generate secure random passwords with various options for customization.

Usage examples:
```go
import "github.com/BadgerBadgerBadgerBadger/go-generate-password/pkg/generate"
// Generate a basic password
pg := generate.NewPasswordGenerator()
opts := generate.PasswordOptions{
    Length:    12,
    Lowercase: true,
    Uppercase: true,
}
password, err := pg.Generate(opts)
if err != nil {
    log.Fatalf("Error generating password: %v", err)
}
fmt.Println(password)

// Generate a more complex password
complexOpts := generate.PasswordOptions{
    Length:                   16,
    Lowercase:                true,
    Uppercase:                true,
    Numbers:                  true,
    Symbols:                  true,
    ExcludeSimilarCharacters: true,
    Strict:                   true,
}
complexPassword, err := pg.Generate(complexOpts)
if err != nil {
    log.Fatalf("Error generating password: %v", err)
}
fmt.Println(complexPassword)

// Generate multiple passwords
passwords, err := pg.GenerateMultiple(5, opts)
if err != nil {
    log.Fatalf("Error generating passwords: %v", err)
}
for _, pass := range passwords {
    fmt.Println(pass)
}
```
