package password

import "golang.org/x/crypto/bcrypt"

// Hash takes a plaintext password and returns a secure hash.
func Hash(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// HashWithCost takes a plaintext password and returns a secure hash using the provided cost.
func HashWithCost(plaintext string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), cost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// Verify compares a stored hash with a plaintext candidate.
func Verify(hash string, candidate string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(candidate),
	)
	return err == nil
}

// Cost returns the bcrypt cost factor used to create the hash.
func Cost(hash string) (int, error) {
	return bcrypt.Cost([]byte(hash))
}
