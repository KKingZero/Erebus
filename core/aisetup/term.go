package aisetup

import "golang.org/x/term"

func isTerminalFD(fd int) bool {
	return term.IsTerminal(fd)
}
