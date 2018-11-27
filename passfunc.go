package dns

// PassFunc is used early in the server code to accept or reject a message. When rejecting the returned boolean is false.
type PassFunc func(dh Header) (rcode int, ok bool)

// DefaultPassFunc returns false when the request:
//
// * isn't a request
// * opcode isn't OpcodeQuery or OpcodeNotify
// * Zero bit isn't zero
// * has more than 1 question in the question section
// * has more than 0 RRs in the Answer section
// * has more than 0 RRs in the Authority section
// * has more than 2 RRs in the Additional section
var DefaultPassFunc = func(dh Header) (int, bool) {
	// Don't allow dynamic updates, because then the sections can contain a whole bunch of RRs.
	opcode := int(dh.Bits>>11) & 0xF
	if opcode != OpcodeQuery && opcode != OpcodeNotify {
		return RcodeFormatError, false
	}
	zero := dh.Bits&_Z != 0
	if zero {
		return RcodeFormatError, false
	}
	if dh.Qdcount != 1 {
		return RcodeFormatError, false
	}
	if dh.Ancount != 0 {
		return RcodeFormatError, false
	}
	if dh.Nscount != 0 {
		return RcodeFormatError, false
	}
	if dh.Arcount > 2 {
		return RcodeFormatError, false
	}
	return 0, true
}
