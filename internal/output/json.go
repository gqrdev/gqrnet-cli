package output

import (
	"encoding/json"
	"fmt"

	"gqrnet/internal/domain"
)

// PrintJSON formats and outputs the domain check result in JSON format.
func PrintJSON(res domain.DomainResult) error {
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
