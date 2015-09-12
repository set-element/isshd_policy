#
#
@load isshd_policy/sshd_const.bro
#
# these two are for non v3 transactions - if this is a new install
#    they can be commented out of here.
@load isshd_policy/sshd_analyzer_cluster.bro
@load isshd_policy/sshd_sftp_cluster.bro
#
@load isshd_policy/sshd_core_cluster.bro
@load isshd_policy/sshd_policy_cluster.bro
@load isshd_policy/sshd_sftp3_cluster.bro
@load isshd_policy/sshd_sftp_cluster.bro
#
#@load isshd_policy/sshd_cert_data.bro
@load isshd_policy/sshd_input_stream.bro
