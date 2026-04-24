package decloaker

import "fmt"

var (
	Authors = []string{
		"Gustavo Iñiguez Goya",
	}
	Version = "v0.0.6"
	License = fmt.Sprintf(`Copyright (C) %s
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
	`, Authors[0],
	)
)
