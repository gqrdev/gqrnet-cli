package output

import (
	"encoding/json"
	"fmt"
	"io"

	"gqrnet/internal/domain"
)

// PrintJSON formats and outputs the domain check result in JSON format.
func PrintJSON(w io.Writer, res domain.DomainResult) error {
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
