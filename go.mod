module github.com/hariguchi/go-nat-traversal

go 1.22.0

require (
	github.com/hariguchi/go-execv v0.0.0-20241210002404-0dccc2401cc1
	github.com/hariguchi/go-utils v0.0.0-20241209020745-33d6b9b73222
	github.com/pion/stun/v3 v3.0.0
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/pion/dtls/v3 v3.0.1 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	github.com/wlynxg/anet v0.0.3 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
)

replace github.com/hariguchi/go-utils => ../go-utils
