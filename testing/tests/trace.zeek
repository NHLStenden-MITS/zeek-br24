# @TEST-DOC: Test Zeek parsing a trace file through the BR24 analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/udp-port-12345.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff br24.log

# TODO: Adapt as suitable. The example only checks the output of the event
# handlers.

event BR24::message(c: connection, is_orig: bool, payload: string)
	{
	print fmt("Testing BR24: [%s] [orig_h=%s, orig_p=%s, resp_h=%s, resp_p=%s] %s", (
	    is_orig ? "request" : "reply" ), c$id$orig_h, c$id$orig_p,
	    c$id$resp_h, c$id$resp_p, payload);
	}
