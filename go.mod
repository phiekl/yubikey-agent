module filippo.io/yubikey-agent

go 1.19

require (
	github.com/go-piv/piv-go/v2 v2.0.0
	github.com/twpayne/go-pinentry-minimal v0.0.0-20220113210447-2a5dc4396c2a
	golang.org/x/crypto v0.4.0
	golang.org/x/term v0.3.0
)

require golang.org/x/sys v0.3.0 // indirect

replace github.com/go-piv/piv-go/v2 => github.com/phiekl/piv-go/v2 v2.0.0-20240822214357-a1a7011eed6a
