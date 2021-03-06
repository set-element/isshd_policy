# 01/21/18: Scott Campbell
# v. 0.2
# 
# Framework for converting local policy into analysis of behavior
#
# The idea is that the same events processed by core will also be processed here, except
#  that the local site policy will be audited (and possible enforced ehre).
#
# Remove |s_set| == 0 test as it would fail a two part detection
#

@load isshd_policy/sshd_core_cluster

module SSHD_POLICY;

export {

	redef enum Notice::Type += {
		SSHD_RemoteExecHostile,
		SSHD_Suspicous,
		SSHD_SuspicousThreshold,
		SSHD_Hostile,
		SSHD_BadKey,
		#
		SSHD_POL_InvalUser,
		SSHD_POL_AuthPassAtt,
		SSHD_POL_PassSkip,
		SSHD_POL_ChanPortOpen,
		SSHD_POL_ChanPortFwrd,
		SSHD_POL_ChanPostFwrd,
		SSHD_POL_ChanSetFwrd,
		SSHD_POL_Socks4,
		SSHD_POL_Socks5,
		SSHD_POL_SesInChanOpen,
		SSHD_POL_SesNew,
		SSHD_POL_DirTCPIP,
		SSHD_POL_TunInit,
		SSHD_POL_x11fwd,
	};
	
	######################################################################################
	# Events to alarm - A NOTICE will be made for each of these events if the appropriate
	#   conditions are met.
	# The large number of NOTICEs allows for per notice filtering and actions up to and
	#   including drop actions as wanted.  
	######################################################################################
	# default on - looking at session content as well as looking at remote exec 
	#  quantities
	global channel_data_client_notice = T &redef;
	global channel_data_server_notice = T &redef;
	global channel_notty_analysis_disable_notice = T &redef;
	global channel_notty_server_data_notice = T &redef;
	global channel_notty_client_data_notice = T &redef;
	global session_remote_do_exec_notice = T &redef;
	global session_remote_exec_no_pty_notice = T &redef;
	global session_remote_exec_pty_notice = T &redef;
	#
	global auth_invalid_user_notice = T &redef;
	global auth_pass_attempt_notice = F &redef;
	global channel_pass_skip_notice = F &redef;
	global channel_port_open_notice = F &redef;
	global channel_portfwd_req_notice = F &redef;
	global channel_post_fwd_listener_notice = F &redef;
	global channel_set_fwd_listener_notice = F &redef;
	global channel_socks4_notice = T &redef;
	global channel_socks5_notice = T &redef;
	global session_input_channel_open_notice = F &redef;
	global session_new_notice = F &redef;
	global session_request_direct_tcpip_notice = F &redef;
	global session_tun_init_notice = T &redef;
	global session_x11fwd_notice = F &redef;

	######################################################################################
	#  configuration: delinate individual commands that are interesting in terms
	#    of severity
	######################################################################################

	# suspicous commands 
	global notify_suspicous_command = T &redef;

	global suspicous_threshold: count = 5 &redef;
	global suspicous_command_list: pattern = string_to_pattern(unique_id(""), T) &redef;

	# this set of commands should be alarmed on when executed
	#  remotely
	global alarm_remote_exec: pattern = string_to_pattern(unique_id(""), T) &redef;
	global alarm_remote_exec_whitelist: pattern = string_to_pattern(unique_id(""), T) &redef;

	global user_white_list: pattern = string_to_pattern(unique_id(""), T) &redef;

	# Data formally from login.bro - this has been imported as a basic set with
	#  additional notes put in the local instance init file.  
	#
	global input_trouble: pattern = string_to_pattern(unique_id(""), T) &redef;
	global output_trouble: pattern = string_to_pattern(unique_id(""), T) &redef;

	# lists of regular expressions which might trigger the hostile detect, but 
	#   are actually benign from this context.
	const input_trouble_whitelist: pattern = string_to_pattern(unique_id(""), T) &redef;
	const output_trouble_whitelist: pattern = string_to_pattern(unique_id(""), T) &redef;
	# 
	# data in the form of aa:bb:cc:dd:ee:ff:gg:hh:ii:jj:kk:ll:mm:nn:oo:pp
	global bad_key_list: set[string] &redef;

} # end export

######################################################################################
#  data structs and tables
######################################################################################
# 
# This section has been moved to core to avoid synching issues
#

#########################################################################################
# functions
#########################################################################################

function parse_line(data: string, t: count) : set[string]
{
	# the data field contains some sort of hostile content.
	# we parse through it and return the set of offending commands 
	# if possible.  
	# this as been expanded to allow for multiple types of line parsing
	#
	# note that the whitelist test is run against the entire semicolin delim
	#  set since it is designed to deal with context
	#
	# In order to address multi-part sigs for attack patterns, add a two-part
	#   test for detection. 
	#

	local return_set: set[string];
	local sc_element: count;
	local space_element: count;

	# look for multiple comands separated by ';' since a;b;c will have no strings
	local split_on_sc = split_string(data, /;/);

	for ( sc_element in split_on_sc ) {
		# now split ; separated commands up on space
		local split_on_space = split_string(split_on_sc[sc_element], / /);

		for ( space_element in split_on_space ) {

			# this section is a little gross ...
			if ( t == LINE_SUSPICOUS ) {

				if ( suspicous_command_list in split_on_space[space_element] && 
					split_on_space[space_element] !in return_set) {

		 			add return_set[ split_on_space[space_element] ];
					print fmt("seen LINE_SUSPICOUS command: %s", split_on_space[space_element]);
				}
			} # end LINE_SUSPICOUS

			if ( t == LINE_CLIENT )  {

				if ( (input_trouble in split_on_space[space_element]) && 
					(input_trouble_whitelist !in split_on_space[space_element]) &&
					(split_on_space[space_element] !in return_set) ) {

		 			add return_set[ split_on_space[space_element] ];
					print fmt("seen hostile LINE_CLIENT command: %s", split_on_space[space_element]);
				}
			} # end LINE_CLIENT

			if ( t == LINE_SERVER ) { 
		
				if ( (output_trouble in split_on_space[space_element]) &&
					(output_trouble_whitelist !in split_on_space[space_element]) && 
					(split_on_space[space_element] !in return_set) ) {

		 			add return_set[ split_on_space[space_element] ];
					print fmt("seen hostile LINE_SERVER command: %s", split_on_space[space_element]);
				}
			} # end LINE_SERVER

		}
	} # end ; for sc_element loop

	return return_set;
}


function test_suspicous(data:string, CR: SSHD_CORE::client_record, channel:count, sid:string, cid:count) : int
	{
	# Test URI encoded data string for suspicous commands
	# Note that the data value will be returned to the original byte
	#   values before analysis so that byte values can be test against.  

	local ret= 0; # default return value
	# first look at the entire string to see if it conains any of the 
	#  suspicous expressions
	if ( suspicous_command_list in data ) {

		print fmt("SUS COMM LINE: %s", data);	
		# Now that we know that a value exists that we are intereted in,
		#  spend the additional effort to determine the value.
		# Note that there might be more than one value per line
		local s_set: set[string];
		local s_set_element: string;

		# parse_linr() defined above - this is doing the real work of detection
		s_set = parse_line(data, LINE_SUSPICOUS);	

		# The set 's_set' contains (one/multiple) commands which have been identified as suspicous.
		# Go through them and make sure that the current CR has not counted them already
		for ( s_set_element in s_set ) {

			if ( s_set_element !in CR$s_commands ) {
				add CR$s_commands[s_set_element];
				++ret;

				++CR$suspicous_count;

				if ( (notify_suspicous_command) && (CR$suspicous_count <= suspicous_threshold) ) {
	
					NOTICE([$note=SSHD_Suspicous,
						$msg=fmt("%s %s %s %s %s @ %s -> %s:%s command: %s",
						CR$log_id, channel, sid, cid, CR$uid,
						CR$id$orig_h, CR$id$resp_h, 
						CR$id$resp_p, s_set_element)]);
					}

				# at suspicous_threshold, append commands together
				if ( CR$suspicous_count == suspicous_threshold ) {

					local t_s: string = " ";
					local r_s: string = " ";

					for ( t_s in CR$s_commands ) {
						r_s = fmt("%s %s", r_s, t_s);
					}

					NOTICE([$note=SSHD_SuspicousThreshold,
						$msg=fmt("%s %s %s %s %s @ %s -> %s %s:%s {%s}",
						CR$log_id, channel, sid, cid, CR$uid, 
						CR$id$orig_h, sid, CR$id$resp_h, 
						CR$id$resp_p, r_s)]);
				}
			} # end  s_set_element !in CR$s_commands

		} #end for s_set
	}

	return ret; # return value = count of new suspicous elements
}

# Look for hostile strings in remote exec values
# 
function test_remote_exec(data: string, CR: SSHD_CORE::client_record, sid:string, cid:count) : int
	{
	local ret= 0; # default return value

	if ( alarm_remote_exec in data ) {

		# ... these are not the droids that you are looking for ...
		if ( alarm_remote_exec_whitelist !in data ) {	
			#
			NOTICE([$note=SSHD_RemoteExecHostile,
			$msg=fmt("%s - %s %s %s @ %s -> %s:%s command: %s",
			CR$log_id, sid, cid, CR$uid, 
			CR$id$orig_h, CR$id$resp_h, 
			CR$id$resp_p, data)]);
			
			ret = 1;
			}
		}
		
	return ret;
	}

function test_hostile_client(data:string, CR: SSHD_CORE::client_record, channel:count, sid:string, cid:count) : int
	{
	local ret= 0; # default return value

	if (input_trouble in data) {

		# quick check to see if the whitelist is populated and if
		#   the data is in place
		if ( (|input_trouble_whitelist| > 0) && (input_trouble_whitelist in data) )
			return ret;

		# now extract the offending command(s)
		local s_set: set[string];
		local s_set_element: string = " ";

		s_set = parse_line(data, LINE_CLIENT);	
		local ret_str: string = " ";

		# glue the s_set retuen values together - will be identified separately 
		#   in the NOTICE below
		for ( s_set_element in s_set ) {
			ret_str = fmt("%s %s", ret_str, s_set_element);
		}

		# XXX get test for channel non-exist

		# now make sure the mess is safe to print in the notice
		NOTICE([$note=SSHD_Hostile,
			$msg=fmt("%s %s %s %s %s @ %s -> %s:%s client output:%s [%s]",
				CR$log_id, CR$channel_type[channel], sid, cid, 
				CR$uid, CR$id$orig_h, CR$id$resp_h, CR$id$resp_p, 
				str_shell_escape(data), str_shell_escape(ret_str) )]);

				
		ret = 1;
		}
		
	return ret;
	
	}

function test_hostile_server(data:string, CR: SSHD_CORE::client_record, channel:count, sid:string, cid:count) : int
	{
	local ret= 0; # default return value

	if (output_trouble in data) {

		# quick check to see if the whitelist is populated and if
		#   the data is in place
		if ( (|output_trouble_whitelist| > 0) && (output_trouble_whitelist in data) )
			return ret;

		# now extract the offending command(s)
		local s_set: set[string];
		local s_set_element: string = " ";

		s_set = parse_line(data, LINE_SERVER);	
		local ret_str: string = " ";

		# glue the s_set retuen values together - will be identified separately 
		#   in the NOTICE below
		for ( s_set_element in s_set ) {
			ret_str = fmt("%s %s", ret_str, s_set_element);
		}
	
		NOTICE([$note=SSHD_Hostile,
			$msg=fmt("%s %s %s %s %s @ %s -> %s:%s server output: %s [%s]",
				CR$log_id, CR$channel_type[channel], sid, cid, CR$uid, 
				CR$id$orig_h, CR$id$resp_h, CR$id$resp_p,  
				str_shell_escape(data), str_shell_escape(ret_str) )]);
				
		ret = 1;
		}
		
	return ret;
	
	}

#########################################################################################
# events
#########################################################################################
event auth_invalid_user_3(ts: time, version: string, sid: string, cid: count, uid: string)
{
	if ( auth_invalid_user_notice ) {
		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_InvalUser,
			$msg=fmt("%s %s @ %s -> %s:%s", CR$log_id, uid, 
				CR$id$orig_h, CR$id$resp_h, CR$id$resp_p )]);
	}
}

event auth_key_fingerprint_3(ts: time, version: string, sid: string, cid: count, fingerprint: string, key_type: string)
{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	
	if ( fingerprint in bad_key_list ) {

		NOTICE([$note=SSHD_BadKey,
			$msg=fmt("%s 0 %s %s %s @ %s -> %s:%s %s %s %s",
				CR$log_id, sid, cid, CR$uid,
				CR$id$orig_h, sid, CR$id$resp_h,
				CR$id$resp_p, key_type, fingerprint)]);
	}

}

event auth_pass_attempt_3(ts: time, version: string, sid: string, cid: count, uid: string, password: string)
{
	if ( auth_pass_attempt_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_AuthPassAtt,
			$msg=fmt("%s %s @ %s:%s -> %s:%s", CR$log_id, uid, password,
				CR$id$orig_h, CR$id$resp_h, CR$id$resp_p )]);
	}
}

event channel_data_client_3(ts: time, version: string, sid: string, cid: count, channel:count, data:string)
{
	if ( channel_data_client_notice ) {

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		if ( channel !in CR$channel_type )
			{
				CR$channel_type[channel] = "unknown";
			}

		# run client data through analyzer for both suspicous and hostile content
		test_suspicous(data, CR, channel, sid, cid);
		test_hostile_client(data, CR, channel, sid, cid);
	}

}

event channel_data_server_3(ts: time, version: string, sid: string, cid: count, channel: count, data: string)
{
	if ( channel_data_server_notice ) {

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		if ( channel !in CR$channel_type )
			{
				CR$channel_type[channel] = "unknown";
			}

		# run client data through analyzer for both suspicous and hostile content
		test_suspicous(data, CR, channel, sid, cid);
		test_hostile_server(data, CR, channel, sid, cid);
	}

}


event channel_notty_client_data_3(ts: time, version: string, sid: string, cid: count, channel: count, data: string)
{
	if ( channel_notty_client_data_notice ) {

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		if ( channel !in CR$channel_type )
			{
				CR$channel_type[channel] = "unknown";
			}

		# run client data through analyzer for both suspicous and hostile content
		test_suspicous(data, CR, channel, sid, cid);
		test_hostile_client(data, CR, channel, sid, cid);
	}
}

event channel_notty_server_data_3(ts: time, version: string, sid: string, cid: count, channel: count, data: string)
{
	if ( channel_notty_server_data_notice ) {

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		if ( channel !in CR$channel_type )
			{
				CR$channel_type[channel] = "unknown";
			}

		# run server data through analyzer for both suspicous and hostile content
		test_suspicous(data, CR, channel, sid, cid);
		test_hostile_server(data, CR, channel, sid, cid);
	}
}

event channel_pass_skip_3(ts: time, version: string, sid: string, cid: count, channel: count)
{
	if ( channel_pass_skip_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_PassSkip,
			$msg=fmt("%s %s @ %s:%s", CR$log_id, CR$uid,
				CR$id$resp_h, CR$id$resp_p )]);
	}

}

event channel_port_open_3(ts: time, version: string, sid: string, cid: count, channel: count, rtype: string, l_port: port, path: string, h_port: port, rem_host: string, rem_port: port)
{
	if ( channel_port_open_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_ChanPortOpen,
			$msg=fmt("%s listen port %s for %s %s:%s -> %s:%s",
				CR$log_id, rtype, l_port, rem_host, rem_port, path, h_port)]);
	}

}

event channel_portfwd_req_3(ts: time, version: string, sid: string, cid: count, channel:count, host: string, fwd_port: count)
{
	if ( channel_portfwd_req_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_ChanPortFwrd,
			$msg=fmt("%s %s:%s", CR$log_id, host, fwd_port)]);
	}
}

event channel_post_fwd_listener_3(ts: time, version: string, sid: string, cid: count, channel: count, l_port: port, path: string, h_port: port, rtype: string)
{
	if ( channel_post_fwd_listener_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_ChanPostFwrd,
			$msg=fmt("%s %s %s -> %s:%s", 
				CR$log_id, rtype, l_port, path, h_port)]);
	}
}

event channel_set_fwd_listener_3(ts: time, version: string, sid: string, cid: count, channel: count, c_type: count, wildcard: count, forward_host: string, l_port: port, h_port: port)
{
	if ( channel_set_fwd_listener_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_ChanSetFwrd,
			$msg=fmt("%s wc:%s %s -> %s:%s", 
				CR$log_id, wildcard, l_port, forward_host, h_port)]);
	}
}

event channel_socks4_3(ts: time, version: string, sid: string, cid: count, channel: count, path: string, h_port: port, command: count, username: string)
{
	if ( channel_socks4_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_Socks4,
			$msg=fmt("%s command: %s socks4 to %s @ %s:%s", 
				CR$log_id, command, username, path, h_port)]);
	}
}

event channel_socks5_3(ts: time, version: string, sid: string, cid: count, channel: count, path: string, h_port: port, command: count)
{
	if ( channel_socks5_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_Socks5,
			$msg=fmt("%s command: %s[%s] socks5 to %s:%s",
				CR$log_id, socks5_header_types[command], command, path, h_port)]);
	}
}

event session_input_channel_open_3(ts: time, version: string, sid: string, cid: count, tpe: count, ctype: string, rchan: int, rwindow: int, rmaxpack: int)
{
	if ( session_input_channel_open_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_SesInChanOpen,
			$msg=fmt("%s %s ctype %s rchan %d win %d max %d",
				CR$log_id,CR$channel_type[int_to_count(rchan)], 
				ctype, rchan, rwindow, rmaxpack)]);
	}
}

event session_new_3(ts: time, version: string, sid: string, cid: count, pid: int, ver: string)
{
	if ( session_new_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_SesNew,
			$msg=fmt("%s %s", CR$log_id, ver)]);
	}
}

event session_remote_do_exec_3(ts: time, version: string, sid: string, cid: count, channel: count, ppid: count, command: string)
{
	if ( session_remote_do_exec_notice ) {
		# This is called to fork and execute a command.  If another command is
		#  to be forced, execute that instead.

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		#function test_remote_exec(data: string, CR: SSHD_CORE::client_record, sid:string, cid:count) : int
		test_remote_exec(command, CR, sid, cid);
	}

}

event session_remote_exec_no_pty_3(ts: time, version: string, sid: string, cid: count, channel: count, ppid: count, command: string)
{
	if ( session_remote_exec_no_pty_notice ) {
		# This is called to fork and execute a command when we have no tty.  This
		#  will call do_child from the child, and server_loop from the parent after
		#  setting up file descriptors and such.

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		test_remote_exec(command, CR, sid, cid);
	}
}

event session_remote_exec_pty_3(ts: time, version: string, sid: string, cid: count, channel: count, ppid: count, command: string)
{
	if ( session_remote_exec_pty_notice ) {
		# This is called to fork and execute a command when we have a tty.  This
		#  will call do_child from the child, and server_loop from the parent after
		#  setting up file descriptors, controlling tty, updating wtmp, utmp,
		#  lastlog, and other such operations.

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		test_remote_exec(command, CR, sid, cid);
	}
}

event session_request_direct_tcpip_3(ts: time, version: string, sid: string, cid: count, channel: count, originator: string, orig_port: port, target: string, target_port: port, i: count)
{
	if ( session_request_direct_tcpip_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_DirTCPIP,
			$msg=fmt("%s %s:%s -> %s:%s",
				CR$log_id, originator, orig_port, target, target_port)]);
	}
}

event session_tun_init_3(ts: time, version: string, sid: string, cid: count, channel: count, mode: count)
{
	if ( session_tun_init_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_TunInit,
			$msg=fmt("%s %s", CR$log_id, tunnel_type[mode] )]);
	}
}

event session_x11fwd_3(ts: time, version: string, sid: string, cid: count, channel: count, display: string)
{
	if ( session_x11fwd_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_x11fwd,
			$msg=fmt("%s %s", CR$log_id, display)]);
	}
}

# events to modify the key list
#
# see the sshd_key_data.bro file for a bulk input example.
#
event sshd_key_add_hostile(key:string)
	{
	
	if ( key !in bad_key_list ) {
	
		add bad_key_list[key];
		}
		
	}
	
event sshd_key_remove_hostile(key:string)
	{
	
	if ( key in bad_key_list ) {
	
		delete bad_key_list[key];
		}
		
	}
