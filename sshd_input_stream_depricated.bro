#
# Contains the set of version 1 and 2 events that are not normally needed any more 
#   for a site running contemporary iOpenSSH codes
#
@load isshd_policy/sshd_input_stream

module SSHD_IN_STREAM;


function _sftp_process_readlink_2(_data: string) : count
        {
        # event sftp_process_readlink(ts:time, sid:string, cid:count, data:string)

        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_readlink(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_readlink(_data: string) : count
        {
        # event sftp_process_readlink(ts:time, sid:string, cid:count, data:string)

        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_readlink(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_rename(_data: string) : count
        {
        # event sftp_process_rename(ts:time, sid:string, cid:count, old_name:string, new_name:string)

        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );
        local d2 = ssh_string( parts[7] );

        event sftp_process_rename(ts,sid,cid,d,d2);

        return 0;
        }

function _sftp_process_rename_2(_data: string) : count
        {
        # event sftp_process_rename(ts:time, sid:string, cid:count, old_name:string, new_name:string)

        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );
        local d2 = ssh_string( parts[7] );

        event sftp_process_rename(ts,sid,cid,d,d2);

        return 0;
        }

function _sftp_process_setstat_2(_data: string) : count
        {
        # event sftp_process_setstat(ts:time, sid:string, cid:count, data:string)

        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local i = ssh_int( parts[6] );
        local d = ssh_string( parts[7] );

        event sftp_process_setstat(ts,sid,cid,d);

        return 0;
        }

function _auth_ok(_data: string) : count
        {
        # event auth_ok(ts:time, sid:string, uid:string, authtype:string, s_addr: addr, s_port: port, r_addr: addr, r_port: port, cid: count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local uid = ssh_string( parts[5] );
        local authtype = ssh_string( parts[6] );
        local s_addr = ssh_addr( parts[7] );
        local s_port = ssh_port( parts[8] );
        local r_addr = ssh_addr( parts[9] );
        local r_port = ssh_port( parts[10] );
        local cid = ssh_count( parts[11] );

        event auth_ok_2(ts,version,serv_interfaces,sid,uid,authtype,s_addr,s_port,r_addr,r_port,cid);

        return 0;
        }

function _auth_ok_2(_data: string) : count
        {
        # event auth_ok_2(ts:time, version: string, serv_interfaces: string, sid:string, uid:string, authtype:string, s_addr: addr, s_port: port, r_addr: addr, r_port: port, cid: count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local uid = ssh_string( parts[5] );
        local authtype = ssh_string( parts[6] );
        local s_addr = ssh_addr( parts[7] );
        local s_port = ssh_port( parts[8] );
        local r_addr = ssh_addr( parts[9] );
        local r_port = ssh_port( parts[10] );
        local cid = ssh_count( parts[11] );

        event auth_ok_2(ts,version,serv_interfaces,sid,uid,authtype,s_addr,s_port,r_addr,r_port,cid);
        return 0;
        }

function _data_server_sum(_data: string) : count
        {
        # data_server_sum time=1342001137.222595 uristring=4549_cvrsvc01_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.5+128.55.56.5+128.
        # 55.69.224+128.55.33.224+ count=441292721 count=0 count=11123
        # data_server_sum(ts: time, sid: string, version: string, serv_interfaces: string,cid: count, channel: count, bytes_skip: count)
        # Q: last set in order ??
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local channel = ssh_count( parts[6] );
        local bytes_skip = ssh_count( parts[7] );

        event data_server_sum(ts,sid,version,serv_interfaces,cid,channel,bytes_skip);

        return 0;
        }

function _data_server_sum_2(_data: string) : count
        {
        # data_server_sum time=1342001137.222595 uristring=4549_cvrsvc01_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.5+128.55.56.5+128.
        # 55.69.224+128.55.33.224+ count=441292721 count=0 count=11123
        # data_server_sum(ts: time, sid: string, version: string, serv_interfaces: string,cid: count, channel: count, bytes_skip: count)
        # Q: last set in order ??
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local channel = ssh_count( parts[6] );
        local bytes_skip = ssh_count( parts[7] );

        event data_server_sum_2(ts,sid,version,serv_interfaces,cid,channel,bytes_skip);

        return 0;
        }

function _channel_exit(_data: string) : count
        {
        #print fmt("skipping _channel_exit %s", _data);
        return 0;
        }

function _channel_exit_2(_data: string) : count
        {
        #
        #print fmt("skipping _channel_exit_2 %s", _data);
        return 0;
        }

function _data_client(_data: string) : count
        {
        # event data_client(ts:time, sid:string, cid:count, channel:count, _data:string)
        # data_client time=1342000801.342046 uristring=8247_hopper08_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.77.1.9+128.55.68.39+128.55.34.73+10.10.10.207+10.10.30.207+10.10.20.208+ count=627016360 count=0 uristring=p%7Fcd+C%09
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local channel = ssh_count( parts[6] );
        local d = ssh_string( parts[7] );

        event data_client_2(ts,sid,version,serv_interfaces,cid,channel,d);

        return 0;
        }

function _data_client_2(_data: string) : count
        {
        # event data_client_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local channel = ssh_count( parts[6] );
        local d = ssh_string( parts[7] );

        event data_client_2(ts,version,serv_interfaces,sid,cid,channel,d);

        return 0;
        }

function _data_server(_data: string) : count
        {
        # event data_server(ts:time, sid:string, cid:count, channel:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local channel = ssh_count( parts[6] );
        local d = ssh_string( parts[7] );

        event data_server_2(ts,version,serv_interfaces,sid,cid,channel,d);

        return 0;
        }

function _data_server_2(_data: string) : count
        {
        # event data_server_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local channel = ssh_count( parts[6] );
        local d = ssh_string( parts[7] );

        event data_server_2(ts,version,serv_interfaces,sid,cid,channel,d);

        return 0;
        }

function data_server_sum(_data: string) : count
        {
        return 0;
        }

function data_server_sum_2(_data: string) : count
        {
        #
        return 0;
        }

function _new_channel_session(_data: string) : count
        {
        # event new_channel_session(ts:time, sid:string, channel:count, channel_type:string, cid:count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local channel = ssh_count( parts[5] );
        local channel_type = ssh_string( parts[6] );
        local cid = ssh_count( parts[7] );

        event new_channel_session_2(ts,version,serv_interfaces,sid,channel,channel_type,cid);

        return 0;
        }

function _new_channel_session_2(_data: string) : count
        {
        # event new_channel_session_2(ts:time, version: string, serv_interfaces: string, sid:string, channel:count, channel_type:string, cid:count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local channel = ssh_count( parts[5] );
        local channel_type = ssh_string( parts[6] );
        local cid = ssh_count( parts[7] );

        event new_channel_session_2(ts,version,serv_interfaces,sid,channel,channel_type,cid);

        return 0;
        }

function _new_session(_data: string) : count
        {
        # event new_session(ts:time, sid:string, version:string, cid:count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local ver = ssh_string( parts[5] );
        local cid = ssh_count( parts[6] );

        event new_session_2(ts,version,serv_interfaces,sid,ver,cid);

        return 0;
        }

function _new_session_2(_data: string) : count
        {
        # event new_session_2(ts:time, version: string, serv_interfaces: string, sid:string, ver:string, cid:count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local ver = ssh_string( parts[5] );
        local cid = ssh_count( parts[6] );

        event new_session_2(ts,version,serv_interfaces,sid,ver,cid);

        return 0;
        }

function _notty_analysis_disable(_data: string) : count
        {
        # event notty_analysis_disable(ts:time, sid:string, cid:count, byte_skip: count, byte_allow: count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local byte_skip = ssh_int( parts[6] );
        local byte_allow = ssh_int( parts[7] );

        event notty_analysis_disable_2(ts,version,serv_interfaces,sid,cid,byte_skip,byte_allow);

        return 0;
        }

function _notty_analysis_disable_2(_data: string) : count
        {
        # event notty_analysis_disable_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, byte_skip: int, byte_allow: int)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local byte_skip = ssh_int( parts[6] );
        local byte_allow = ssh_int( parts[7] );

        event notty_analysis_disable_2(ts,version,serv_interfaces,sid,cid,byte_skip,byte_allow);

        return 0;
        }

function _notty_client_data(_data: string) : count
        {
        # event notty_client_data(ts:time, sid:string, cid:count, channel:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local channel = ssh_count( parts[6] );
        local d = ssh_string( parts[7] );

        event notty_client_data_2(ts,version,serv_interfaces,sid,cid,channel,d);

        return 0;
        }

function _notty_client_data_2(_data: string) : count
        {
        # event notty_client_data_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local channel = ssh_count( parts[6] );
        local d = ssh_string( parts[7] );

        event notty_client_data_2(ts,version,serv_interfaces,sid,cid,channel,d);

        return 0;
        }

function _notty_server_data(_data: string) : count
        {
        # event notty_server_data(ts:time, sid:string, cid:count, channel:count, _data:string)
        # notty_server_data time=1354513238.109957 uristring=32095_nid06135_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.128.24.40+10.10.20.101+ count=979185324 count=0
        #  uristring=XXRETCODE:0
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local channel = ssh_count( parts[6] );
        local d = ssh_string( parts[7] );

        event notty_server_data_2(ts,version,serv_interfaces,sid,cid,channel,d);

        return 0;
        }

function _notty_server_data_2(_data: string) : count
        {
        # event notty_server_data_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, _data:string)
        # notty_server_data_2 time=1354513239.716295 uristring=4436_dtn01_22 uristring=NMOD_2.11 uristring=127.0.0.1+10.55.46.155+128.55.32.199+128.55.80.35+ count=9195
        # 55488 count=0 uristring=220+dtn01.nersc.gov+GridFTP+Server+3.33+(gcc64dbg,+1305148829-80)+%5BGlobus+Toolkit+5.0.4%5D+ready
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local channel = ssh_count( parts[6] );
        local d = ssh_string( parts[7] );

        event notty_server_data_2(ts,version,serv_interfaces,sid,cid,channel,d);

        return 0;
        }

function _server_heartbeat(_data: string) : count
        {
        return 0;
        # event server_heartbeat(ts: time, sid: string, dt: count)
        # server_heartbeat time=1342000801.940728 uristring=4582_cvrsvc09_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.13+128.55.56.13+128.55.69.232+128.55.33.232+ count=0
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local dt = ssh_count( parts[5] );

        #print "skipping event server_heartbeat(ts,sid,dt)";
        }


function _server_heartbeat_2(_data: string) : count
        {
        return 0;

        # event server_heartbeat_2(ts: time, version: string, serv_interfaces: string, sid: string, dt: count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local dt = ssh_count( parts[5] );

        #print "skipping event server_heartbeat_2(ts,version,serv_interfaces,sid,dt)";

        #return 0;
        }

function _server_input_channel_open(_data: string) : count
        {
        #print fmt("skipping channel_exit %s", _data);
        return 0;
        }

function _server_input_channel_open_2(_data: string) : count
        {
        # no id'd event, see:
        #  server_input_channel_open_2 time=1342001102.115794 uristring=7340_dtn01_22 uristring=NMOD_2.11 uristring=127.0.0.1+10.55.46.155+128.55.32.199+128.55.80.35+ u ristring=session int=0 int=2097152 int=32768
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local s1 = ssh_string( parts[5] );
        local i1 = ssh_int( parts[6] );
        local i2 = ssh_int( parts[7] );
        local i3 = ssh_int( parts[8] );

        return 0;
        }

function _server_request_direct_tcpip(_data: string) : count
        {
        # event server_request_direct_tcpip(ts:time, sid:string, s_addr:string, s_port: port, r_addr: string, r_port: port, cid: count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local s_addr = ssh_string( parts[5] );
        local s_port = ssh_port( parts[6] + "/tcp" );
        local r_addr = ssh_string( parts[7] );
        local r_port = ssh_port( parts[8] + "/tcp" );
        local cid = ssh_count( parts[9] );

        #event server_request_direct_tcpip(ts,sid,s_addr,s_port,r_addr,r_port,cid);

        return 0;
        }

function _server_request_direct_tcpip_2(_data: string) : count
        {
        # vent server_request_direct_tcpip_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:string, s_port: port, r_addr: string, r_port: port, cid: count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local s_addr = ssh_string( parts[5] );
        local s_port = ssh_port( parts[6] );
        local r_addr = ssh_string( parts[7] );
        local r_port = ssh_port( parts[8] );
        local cid = ssh_count( parts[9] );

        event server_request_direct_tcpip_2(ts,version,serv_interfaces,sid,s_addr,s_port,r_addr,r_port,cid);

        return 0;
        }

function _sftp_process_close(_data: string) : count
        {
        # event sftp_process_close(ts:time, sid:string, cid:count, id: int, handle:int)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local id = ssh_int( parts[6] );
        local handle = ssh_int( parts[7] );

        event sftp_process_close(ts,sid,cid,id,handle);
        return 0;

        }

function _sftp_process_close_2(_data: string) : count
        {
        # event sftp_process_close(ts:time, sid:string, cid:count, id: int, handle:int)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local cid = ssh_count( parts[3] );
        local id = ssh_int( parts[4] );
        local handle = ssh_int( parts[5] );

        event sftp_process_close(ts,sid,cid,id,handle);
        return 0;

        }


function _sftp_process_do_stat(_data: string) : count
        {
        # event sftp_process_do_stat(ts:time, sid:string, cid:count, _data:string)
        # event sftp_process_do_stat(ts:time, sid:string, version: string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_do_stat(ts,sid,version,cid,d);

        return 0;
        }

function _sftp_process_do_stat_2(_data: string) : count
        {
        # event sftp_process_do_stat(ts:time, sid:string, cid:count, _data:string)
        # event sftp_process_do_stat(ts:time, sid:string, version: string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_do_stat(ts,sid,version,cid,d);

        return 0;
        }

function _sftp_process_fsetstat(_data: string) : count
        {
        # event sftp_process_fsetstat(ts:time, sid:string, cid:count, _data:string)
        # sftp_process_fsetstat time=1342724316.473862 uristring=32470_cvrsvc02_22 uristring=NMOD_2.9
        #  uristring=127.0.0.1+10.1.64.6+128.55.56.6+128.55.69.225+128.55.33.225+
        #  count=0 int=185 uristring=/global/u2/b/bnlcat/work/TiO2/RuTi_formate/RuTi_formate_06.msi
        #
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local ppid = ssh_int( parts[6] );
        local d = ssh_string( parts[7] );

        event sftp_process_fsetstat(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_fstat(_data: string) : count
        {
        # event sftp_process_fstat(ts:time, sid:string, cid:count, data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_fstat(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_init(_data: string) : count
        {
        # sftp_process_init(ts:time, sid:string, version:string, serv_interfaces:string, cid:count, uid:string, a:addr)
        # sftp_process_init time=1350046754.477520 uristring=5854_cvrsvc01_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.5+128.55.56.5+128.55.69.224+128.55.33.224+ count=0 uristring=yiwang62 addr=128.118.156.18
        # sftp_process_init time=1350046754.499153 uristring=5854_cvrsvc01_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.5+128.55.56.5+128.55.69.224+128.55.33.224+ count=0 int=3
        #
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );

        local uid: string = "HOLDING";
        local a: addr = ssh_addr("addr=127.0.0.1");

        if ( |parts| > 7 ) {
                uid = ssh_string( parts[6] );
                a = ssh_addr( parts[7] );
                }

        event sftp_process_init(ts,sid,version,serv_interfaces,cid,uid,a);

        return 0;
        }

function _sftp_process_open(_data: string) : count
        {
        # event sftp_process_open(ts:time, sid:string, cid:count, _data:string)
        # sftp_process_open time=1342723860.9219 uristring=11093_cvrsvc01_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.5+128.55.56.5+128.55.69.224+128.55.33.224+ count=0 uristring=/global/u2/a/amkessel/kdtree/cpu_prune/cpu_prune.cpp
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_open(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_opendir(_data: string) : count
        {
        # event sftp_process_opendir(ts:time, sid:string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_opendir(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_opendir_2(_data: string) : count
        {
        # event sftp_process_opendir(ts:time, sid:string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_opendir(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_readdir(_data: string) : count
        {
        # event sftp_process_readdir(ts:time, sid:string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_readdir(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_readdir_2(_data: string) : count
        {
        # event sftp_process_readdir_2(ts:time, sid:string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_readdir(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_realpath(_data: string) : count
        {
        # event sftp_process_realpath(ts:time, sid:string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_realpath(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_remove(_data: string) : count
        {
        # event sftp_process_remove(ts:time, sid:string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_remove(ts,sid,cid,d);

        return 0;
        }

function _ssh_connection_end(_data: string) : count
        {
        # event ssh_connection_end(ts:time, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local s_addr = ssh_addr( parts[5] );
        local s_port = ssh_port( parts[6] );
        local r_addr = ssh_addr( parts[7] );
        local r_port = ssh_port( parts[8] );
        local cid = ssh_count( parts[9] );

        event ssh_connection_end_2(ts,version,serv_interfaces,sid,s_addr,s_port,r_addr,r_port,cid);

        return 0;
        }

function _ssh_connection_end_2(_data: string) : count
        {
        # event ssh_connection_end_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local s_addr = ssh_addr( parts[5] );
        local s_port = ssh_port( parts[6] );
        local r_addr = ssh_addr( parts[7] );
        local r_port = ssh_port( parts[8] );
        local cid = ssh_count( parts[9] );

        event ssh_connection_end_2(ts,version,serv_interfaces,sid,s_addr,s_port,r_addr,r_port,cid);

        return 0;
        }

function _ssh_connection_start(_data: string) : count
        {
        # event ssh_connection_start(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
        # event ssh_connection_start(ts:time, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        #local version = ssh_string( parts[2] );
        #local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local s_addr = ssh_addr( parts[5] );
        local s_port = ssh_port( parts[6] );
        local r_addr = ssh_addr( parts[7] );
        local r_port = ssh_port( parts[8] );
        local cid = ssh_count( parts[9] );

        #event ssh_connection_start(ts,sid,s_addr,s_port,r_addr,r_port,cid);

        return 0;
        }

function _ssh_connection_start_2(_data: string) : count
        {
        # event ssh_connection_start_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local s_addr = ssh_addr( parts[5] );
        local s_port = ssh_port( parts[6] );
        local r_addr = ssh_addr( parts[7] );
        local r_port = ssh_port( parts[8] );
        local cid = ssh_count( parts[9] );

        event ssh_connection_start_2(ts,version,serv_interfaces,sid,s_addr,s_port,r_addr,r_port,cid);

        return 0;
        }
function _sshd_key_fingerprint(_data: string) : count
        {
        # event sshd_key_fingerprint(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, fingerprint:string, key_type:string)yy
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local version = ssh_string( parts[2] );
        local serv_interfaces = ssh_string( parts[3] );
        local sid = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local fingerprint = ssh_string( parts[6] );
        local key_type = ssh_string( parts[7] );

        event sshd_key_fingerprint_2(ts,version,serv_interfaces,sid,cid,fingerprint,key_type);

        return 0;
        }

function _sshd_key_fingerprint_2(_data: string) : count
        {
        # event sshd_key_fingerprint_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, fingerprint:string, key_type:string)yy
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local fingerprint = ssh_string( parts[6] );
        local key_type = ssh_string( parts[7] );

        event sshd_key_fingerprint_2(ts,sid,version,sid,cid,fingerprint,key_type);
        return 0;
        }

function _ssh_login_fail(_data: string) : count
        {
        # no identified event
        return 0;
        }

function _ssh_login_fail_2(_data: string) : count
        {
        return 0;
        }

function _ssh_remote_do_exec(_data: string) : count
        {
        # event ssh_remote_do_exec(ts:time, sid:string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event ssh_remote_do_exec_2(ts,sid,version,serv_interfaces,cid,d);

        return 0;
        }

function _ssh_remote_do_exec_2(_data: string) : count
        {
        # event ssh_remote_do_exec_2(ts:time, sid:string, version:string, serv_interfaces: string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event ssh_remote_do_exec_2(ts,sid,version,serv_interfaces,cid,d);

        return 0;
        }

function _ssh_remote_exec_no_pty(_data: string) : count
        {
        # event ssh_remote_exec_no_pty_2(ts:time, sid:string, version:string, serv_interfaces:string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event ssh_remote_exec_no_pty_2(ts,sid,version,serv_interfaces,cid,d);

        return 0;
        }

function _ssh_remote_exec_no_pty_2(_data: string) : count
        {
        # event ssh_remote_exec_no_pty_2(ts:time, sid:string, version:string, serv_interfaces:string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event ssh_remote_exec_no_pty_2(ts,sid,version,serv_interfaces,cid,d);

        return 0;
        }

function _ssh_remote_exec_pty(_data: string) : count
        {
        # event ssh_remote_exec_pty(ts:time, sid:string, cid:count, _data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local cid = ssh_count( parts[3] );
        local d = ssh_string( parts[4] );

        event ssh_remote_exec_pty_2(ts,sid,cid,d);

        return 0;
        }

function _sftp_process_symlink(_data: string) : count
        {
        # event event sftp_process_symlink(ts:time, sid:string, cid:count, old_path:string, new_path:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local cid = ssh_count( parts[3] );
        local old_path = ssh_string( parts[4] );
        local new_path = ssh_string( parts[5] );

        event sftp_process_symlink(ts,sid,cid,old_path,new_path);

        return 0;
        }

function _sftp_process_mkdir(_data: string) : count
        {
        # event sftp_process_mkdir(ts:time, sid:string, cid:count, data:string)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local cid = ssh_count( parts[5] );
        local d = ssh_string( parts[6] );

        event sftp_process_mkdir(ts,sid,cid,d);

        return 0;
        }

function _invalid_user(_data: string) : count
        {
        #event invalid_user(ts:time, sid:string, version: string, interface:string, uid:string, cid: count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local interface = ssh_string( parts[4] );
        local uid = ssh_string( parts[5] );
        local cid = ssh_count( parts[6] );

        event invalid_user_2(ts,sid,version,interface,uid,cid);

        return 0;
        }

function _invalid_user_2(_data: string) : count
        {
        #event invalid_user_2(ts:time, sid:string, version: string, serv_interfaces: string, uid:string, cid: count)
        local parts = split_string(_data, kv_splitter);

        local ts = ssh_time( parts[1] );
        local sid = ssh_string( parts[2] );
        local version = ssh_string( parts[3] );
        local serv_interfaces = ssh_string( parts[4] );
        local uid = ssh_string( parts[5] );
        local cid = ssh_count( parts[6] );

        event invalid_user_2(ts,sid,version,serv_interfaces,uid,cid);

        return 0;
        }


redef dispatcher += {
        ["PASS_XXX"] = _pass_xxx,
        ["auth_ok"] = _auth_ok,
        ["auth_ok_2"] = _auth_ok_2,
        ["channel_exit"] = _channel_exit,
        ["channel_exit_2"] = _channel_exit_2,
        ["data_client"] = _data_client,
        ["data_client_2"] = _data_client_2,
        ["data_server"] = _data_server,
        ["data_server_2"] = _data_server_2,
        ["data_server_sum"] = _data_server_sum,
        ["data_server_sum_2"] = _data_server_sum_2,
        ["new_channel_session"] = _new_channel_session,
        ["new_channel_session_2"] = _new_channel_session_2,
        ["new_session"] = _new_session,
        ["new_session_2"] = _new_session_2,
        ["notty_analysis_disable"] = _notty_analysis_disable,
        ["notty_analysis_disable_2"] = _notty_analysis_disable_2,
        ["notty_client_data"] = _notty_client_data,
        ["notty_client_data_2"] = _notty_client_data_2,
        ["notty_server_data"] = _notty_server_data,
        ["notty_server_data_2"] = _notty_server_data_2,
        ["server_heartbeat"] = _server_heartbeat,
        ["server_heartbeat_2"] = _server_heartbeat_2,
        ["server_input_channel_open"] = _server_input_channel_open,
        ["server_input_channel_open_2"] = _server_input_channel_open_2,
        ["server_request_direct_tcpip"] = _server_request_direct_tcpip,
        ["server_request_direct_tcpip_2"] = _server_request_direct_tcpip_2,
        ["sftp_process_close"] = _sftp_process_close,
        ["sftp_process_close_2"] = _sftp_process_close_2,
        ["sftp_process_do_stat"] = _sftp_process_do_stat,
        ["sftp_process_do_stat_2"] = _sftp_process_do_stat_2,
        ["sftp_process_fsetstat"] = _sftp_process_fsetstat,
        ["sftp_process_init"] = _sftp_process_init,
        ["sftp_process_init_2"] = _sftp_process_init,
        ["sftp_process_mkdir"] = _sftp_process_mkdir,
        ["sftp_process_open"] = _sftp_process_open,
        ["sftp_process_open_2"] = _sftp_process_open,
        ["sftp_process_opendir"] = _sftp_process_opendir,
        ["sftp_process_opendir_2"] = _sftp_process_opendir_2,
        ["sftp_process_readdir"] = _sftp_process_readdir,
        ["sftp_process_readdir_2"] = _sftp_process_readdir_2,
        ["sftp_process_rename"] = _sftp_process_rename,
        ["sftp_process_rename_2"] = _sftp_process_rename_2,
        ["sftp_process_realpath"] = _sftp_process_realpath,
        ["sftp_process_remove"] = _sftp_process_remove,
        ["sftp_process_readlink"] = _sftp_process_readlink,
        ["sftp_process_readlink_2"] = _sftp_process_readlink_2,
        ["sftp_process_setstat"] = _sftp_process_setstat_2,
        ["sftp_process_setstat_2"] = _sftp_process_setstat_2,
        ["sftp_process_fstat"] = _sftp_process_fstat,
        ["sftp_process_fstat_2"] = _sftp_process_fstat,
        ["sftp_process_symlink"] = _sftp_process_symlink,
        ["ssh_connection_end"] = _ssh_connection_end,
        ["ssh_connection_end_2"] = _ssh_connection_end_2,
        ["ssh_connection_start"] = _ssh_connection_start,
        ["ssh_connection_start_2"] = _ssh_connection_start_2,
        ["sshd_key_fingerprint"] = _sshd_key_fingerprint,
        ["sshd_key_fingerprint_2"] = _sshd_key_fingerprint_2,
        ["ssh_login_fail"] = _ssh_login_fail,
        ["ssh_login_fail_2"] = _ssh_login_fail_2,
        ["ssh_remote_do_exec"] = _ssh_remote_do_exec,
        ["ssh_remote_do_exec_2"] = _ssh_remote_do_exec_2,
        ["ssh_remote_exec_no_pty"] = _ssh_remote_exec_no_pty,
        ["ssh_remote_exec_no_pty_2"] = _ssh_remote_exec_no_pty_2,
        ["ssh_remote_exec_pty"] = _ssh_remote_exec_pty,
        ["invalid_user_2"] = _invalid_user_2,
        };


redef argument_count += {
        ["auth_ok_2"] = vector( 12 ),
        ["auth_ok"] = vector( 12 ),
        ["data_client_2"] = vector( 8 ),
        ["data_server_2"] = vector( 9 ),
        ["data_client"] = vector( 8 ),
        ["data_server"] = vector( 9 ),
        ["data_server_sum_2"] = vector( 8 ),
        ["data_server_sum"] = vector( 8 ),
        ["invalid_user_2"] = vector( 7 ),
        ["new_channel_session"] = vector( 8 ),
        ["new_channel_session_2"] = vector( 8 ),
        ["new_session_2"] = vector( 7 ),
        ["notty_analysis_disable_2"] = vector( 8 ),
        ["notty_client_data"] = vector( 8 ),
        ["notty_client_data_2"] = vector( 8 ),
        ["notty_server_data"] = vector( 8 ),
        ["notty_server_data_2"] = vector( 8 ),
        ["server_request_direct_tcpip_2"] = vector( 10 ),
        ["server_heartbeat"] = vector( 6 ),
        ["server_heartbeat_2"] = vector( 6 ),
        ["sftp_process_close"] = vector( 8 ),
        ["sftp_process_do_stat"] = vector( 7 ),
        ["sftp_process_fsetstat"] = vector( 8 ),
        ["sftp_process_fstat"] = vector( 8 ),
        ["sftp_process_init"] = vector( 8 ),
        ["sftp_process_mkdir"] = vector( 7 ),
        ["sftp_process_open"] = vector( 7 ),
        ["sftp_process_opendir"] = vector( 7 ),
        ["sftp_process_readdir"] = vector( 7 ),
        ["sftp_process_readlink"] = vector( 7 ),
        ["sftp_process_realpath"] = vector( 7 ),
        ["sftp_process_remove"] = vector( 7 ),
        ["sftp_process_rename"] = vector( 6 ),
        ["sftp_process_setstat"] = vector( 8 ),
        ["sftp_process_symlink"] = vector( 6 ),
        ["ssh_connection_end_2"] = vector( 10 ),
        ["ssh_connection_start"] = vector( 10 ),
        ["ssh_connection_start_2"] = vector( 10 ),
        ["ssh_login_fail"] = vector( 7 ),
        ["ssh_login_fail_2"] = vector( 7 ),
        ["sshd_key_fingerprint"] = vector( 8 ),
        ["sshd_key_fingerprint_2"] = vector( 8 ),
        ["ssh_remote_do_exec_2"] = vector( 7 ),
        ["ssh_remote_exec_no_pty_2"] = vector( 7 ),
        ["ssh_remote_exec_pty_2"] = vector( 5 ),
        ["channel_exit_2"] = vector( 8 ),
        ["channel_exit"] = vector( 8 ),
        ["new_session"] = vector( 7 ),
        ["notty_analysis_disable"] = vector( 8 ),
        ["PASS_XXX"] = vector( 6 ),
        ["server_input_channel_open"] = vector( 9 ),
        ["server_input_channel_open_2"] = vector( 9 ),
        ["server_request_direct_tcpip"] = vector( 10 ),
        ["sftp_process_close_2"] = vector( 8 ),
        ["sftp_process_do_stat_2"] = vector( 7 ),
        ["sftp_process_fstat_2"] = vector( 7 ),
        ["sftp_process_init_2"] = vector( 8 ),
        ["sftp_process_open_2"] = vector( 7 ),
        ["sftp_process_opendir_2"] = vector( 7 ),
        ["sftp_process_readdir_2"] = vector( 7 ),
        ["sftp_process_readlink_2"] = vector( 7 ),
        ["ssh_connection_end"] = vector( 10 ),
        ["ssh_remote_do_exec"] = vector( 7 ),
        ["ssh_remote_exec_no_pty"] = vector( 7 ),
        ["ssh_remote_exec_pty"] = vector( 7 ),
        };





