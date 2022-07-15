# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seek-basic) begin
(seek-basic) end
seek-basic: exit(0)
EOF
pass;