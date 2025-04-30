@load base/protocols/conn/removal-hooks

module BR24;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register BR24 for.
	const ports = {
		6678/udp,
		6680/udp,
	} &redef;

	type reg_number: enum { 
		radar_ops = 1,  # TODO: change that to a name similar to wireshar;
		zoom_level = 3, 
		unknown_reg_1 = 4, 
		bearing_alignment = 5,
		filters_and_preprocessing = 6,
		interference_rejection = 8,
		target_expansion = 9,
		target_boost = 10,
		local_interference_filter = 14,
		scan_speed = 15,
		noise_rejection = 33,
		target_separation = 34,
		doppler = 35,
		antenna_height = 48,
		keep_alive = 160
	};

	type reg_command: enum { 
		read = 194,
		write = 193, 
	};

	## Record type containing the column fields of the BR24 log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		# TODO: Adapt subsequent fields as needed.

		start_marker: string  &log &optional;
		scanlines_no: count  &log &optional;
		scanline_size: count  &log &optional;

		scanline_header_len: vector of count &log &optional;
		scanline_counter: vector of count &log &optional;
		status: vector of count &log &optional;
		marking: vector of string &log &optional;
		angle: vector of count &log &optional;
		heading: vector of count &log &optional;
		range: vector of count &log &optional;
		unknown_1: vector of string &log &optional;
		scanline_pixels: vector of string &log &optional;
		
		register: reg_number &log &optional;
		command: reg_command &log &optional;
		register_data: string &log &optional;
		
		#payload: string  &log &optional;

		## Request-side payload.
		#request: string &optional &log;

		## Since this is UPD multicast we do not have reply

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


function set_scanline(c: connection){
	c$br24$scanline_header_len = vector();
	c$br24$status = vector();
	c$br24$scanline_counter = vector();
	c$br24$marking = vector();
	c$br24$angle = vector();
	c$br24$heading = vector();
	c$br24$range = vector();
	c$br24$unknown_1 = vector();

	c$br24$scanline_pixels = vector();
}


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

	# c$br24 = Info($ts=network_time(), $uid=c$uid, $id=c$id, $start_marker=c$start_marker, $scanlines_no=c$scanlines_no, $scanline_size=c$scanline_size);

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
event BR24::img_header(c: connection, is_orig: bool, start_marker: string, scanlines_no: count, scanline_size: count)
	{
	hook set_session(c);

	local info = c$br24;

	if ( is_orig) {

		# print "IMG Header Here!", start_marker, scanlines_no, scanline_size;
		
		# TODO: No need to log the start marker?
		info$start_marker = start_marker;
		info$scanlines_no = scanlines_no;
		info$scanline_size = scanline_size;

		# print "Info:", info;

		
	}
	

	hook finalize_br24(c);
	}

event BR24::img_scanline(c: connection, scanline_header_len : count , status: count, scanline_counter: count, marking: string, angle: count, heading: count, range: count, unknown_1: string, scanline_pixels: string)
	{
	hook set_session(c);

	local info = c$br24;
	if ( !info?$scanline_header_len || !info?$status || !info?$scanline_counter
		|| !info?$marking || !info?$angle || !info?$heading
		|| !info?$range || !info?$unknown_1 || !info?$scanline_pixels){
		set_scanline(c);
	}
	
	info$scanline_header_len += scanline_header_len;
	info$status += status;
	info$scanline_counter += scanline_counter;
	info$marking += marking;
	info$angle += angle;
	info$heading += heading;
	info$range += range;
	info$unknown_1 += unknown_1;
	
	# NOTE: disabled to reduce ouput
	#info$scanline_pixels += scanline_pixels;

	# print "Scanline Header Here!:", info;
	
	}

event BR24::reg(c: connection, is_orig: bool, register: reg_number, command: reg_command, data: string)
	{
	hook set_session(c);

	local info = c$br24;
	
	if ( is_orig) {

		# set_scanline(c);

		# print "Reg Here!", register, command, data;

		info$register = register;
		info$command = command;
		info$register_data = data;
		
	}
	

	hook finalize_br24(c);
	}

hook finalize_br24(c: connection)
	{
	# TODO: For UDP protocols, you may want to do this after every request
	# and/or reply.
	emit_log(c);
	}
