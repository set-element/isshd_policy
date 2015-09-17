# isshd_policy
cluster friendly policy for isshd data

This policy depricates any policy from previous versions.
The string() deprication has been addressed for =< 2.4 so there may be issues with 
    running the code on less than this version.

The file functions.bif.patch adds a bif to src/analyzer/protocol/http/functions.bif which dramatically improves the readability of the logs by the raw_unescape_URI() function.

If you do not want to use patch, just install the code in src/analyzer/protocol/http/functions.bif and recompile.

-----
Files:

	README.md                    you are here
	__load__.bro                 policy autoloader
	functions.bif.patch          patch for raw_unescape_URI() bif
	init_node.bro                if node is an isshd analyzer and this is a cluster

	sshd_const.bro               const values across the package
	sshd_input_stream.bro        reads text datastream and turns into events
	sshd_core_cluster.bro        log events
	sshd_policy_cluster.bro      apply local sec policy against events
	sshd_sftp3_cluster.bro       log sftp traffic

	sshd_cert_data.bro           list of known poor certs - not tremendous utility in running
	sshd_signatures.bro          list of suspicous and hostile actions

	sshd_sftp_cluster.bro        DEPRICATED: sftp analyzer for older versions of isshd 
	sshd_analyzer_cluster.bro    DEPRECATED: old isshd analyzer
