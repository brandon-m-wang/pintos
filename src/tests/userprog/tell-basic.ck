# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(tell-basic) begin
(tell-basic) end
tell-basic: exit(0)
EOF
pass;