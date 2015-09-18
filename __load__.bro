#
#
@load isshd_policy/sshd_const.bro
#
@load isshd_policy/sshd_core_cluster.bro
@load isshd_policy/sshd_policy_cluster.bro
@load isshd_policy/sshd_sftp3_cluster.bro
#
@load isshd_policy/sshd_input_stream.bro
@load isshd_policy/sshd_signatures
# 
#@load isshd_policy/sshd_cert_data.bro
#
# these are for non v3 transactions - unles you are running very
#   old isshd code, leave these commented out.  If you want to
#   run them, all three need to be commented in at the same time 
#   due to run time dependencies.
#
#@load isshd_policy/sshd_analyzer_cluster.bro
#@load isshd_policy/sshd_sftp_cluster.bro
#@load isshd_policy/sshd_input_stream_deprecated

