// Package kern loads the SentrAI Gate kernel programs and talks to their maps.
package kern

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel gate ../../bpf/gate.bpf.c
