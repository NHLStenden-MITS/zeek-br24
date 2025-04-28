@load base/protocols/conn/removal-hooks

module BR24;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register BR24 for.
	const ports = {
		# TODO: Replace with actual port(s).
		12345/udp,
	} &redef;

	## Record type containing the column fields of the BR24 log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		# TODO: Adapt subsequent fields as needed.

		## Request-side payload.
		request: string &optional &log;
		## Response-side payload.
		reply: string &optional &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into BR24 logging.
	global log_br24: event(rec: Info);

	## BR24 finalization hook.
	global finalize_br24: Conn::RemovalHook;
}

redef record connection += {
	br24: Info &optional;
};

redef likely_server_ports += { ports };

# TODO: If you're going to send file data into the file analysis framework, you
# need to provide a file handle function. This is a simple example that's
# sufficient if the protocol only transfers a single, complete file at a time.
#
# function get_file_handle(c: connection, is_orig: bool): string
#	{
#	return cat(Analyzer::ANALYZER_BR24, c$start_time, c$id, is_orig);
#	}

event zeek_init() &priority=5
	{
	Log::create_stream(BR24::LOG, [$columns=Info, $ev=log_br24, $path="br24", $policy=log_policy]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_BR24, ports);

	# TODO: To activate the file handle function above, uncomment this.
	# Files::register_protocol(Analyzer::ANALYZER_BR24, [$get_file_handle=BR24::get_file_handle ]);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$br24 )
		return;

	c$br24 = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	Conn::register_removal_hook(c, finalize_br24);
	}

function emit_log(c: connection)
	{
	if ( ! c?$br24 )
		return;

	Log::write(BR24::LOG, c$br24);
	delete c$br24;
	}

# Example event defined in br24.evt.
event BR24::message(c: connection, is_orig: bool, payload: string)
	{
	hook set_session(c);

	local info = c$br24;
	if ( is_orig )
		info$request = payload;
	else
		info$reply = payload;
	}

hook finalize_br24(c: connection)
	{
	# TODO: For UDP protocols, you may want to do this after every request
	# and/or reply.
	emit_log(c);
	}
