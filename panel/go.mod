module gamec/panel

go 1.23

require (
	gamec/edge v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.31.0
	golang.org/x/term v0.27.0
)

require golang.org/x/sys v0.28.0 // indirect

replace gamec/edge => ../edge
