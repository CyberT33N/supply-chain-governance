// Package capabilities anchors the shared kernel's capability-pack registry:
// it gives tenants an importable pin target, so the registry module stays
// durable in their tooling module's build list under go mod tidy.
//
// The registry is data that tenants enumerate and read at gate time through
// the integrity-pinned Go module channel. A module that delivers no imported
// package and no tool directive is dropped by go mod tidy, so a tenant keeps
// the registry module pinned with a blank import of this anchor package in
// its tools module:
//
//	import _ "github.com/t33n-software/supply-chain-governance/capabilities"
//
// The anchor carries no behavior and no exported API by design.
package capabilities
