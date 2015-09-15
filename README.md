# isshd_policy
cluster friendly policy for isshd data

This policy depricates any policy from previous versions.
The string() deprication has been addressed for =< 2.4 so there may be issues with 
    running the code on less than this version.

The file functions.bif.patch adds a bif to src/analyzer/protocol/http/functions.bif which dramatically improves the readability of the logs by the raw_unescape_URI() function.

If you do not want to use patch, just install the code in src/analyzer/protocol/http/functions.bif and recompile.
