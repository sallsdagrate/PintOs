# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(wait-bad-child) begin
(exec-exit) run
(child-simple) run
(wait-bad-child) grandchild should be running by now
(wait-bad-child) waiting for grandchild returned: -1
(wait-bad-child) end
EOF
pass;
