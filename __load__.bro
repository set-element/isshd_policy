#
#
@load isshd_policy/sshd_const.bro
#
# these two are for non v3 transactions - unles you are running very
#   old isshd code, leave these commented out
#@load isshd_policy/sshd_analyzer_cluster.bro
#@load isshd_policy/sshd_sftp_cluster.bro
#
@load isshd_policy/sshd_core_cluster.bro
@load isshd_policy/sshd_policy_cluster.bro
@load isshd_policy/sshd_sftp3_cluster.bro
#
@load isshd_policy/sshd_input_stream.bro
@load isshd_policy/sshd_signatures
#@load isshd_policy/sshd_cert_data.bro
