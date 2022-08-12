# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(priority-donate-tree) begin
(priority-donate-tree) Thread b acquired lock c.
(priority-donate-tree) Main thread should have priority 34.  Actual priority: 34.
(priority-donate-tree) Main thread should have priority 34.  Actual priority: 34.
(priority-donate-tree) Thread a acquired lock b.
(priority-donate-tree) Main thread should have priority 37.  Actual priority: 37.
(priority-donate-tree) Main thread should have priority 40.  Actual priority: 40.
(priority-donate-tree) Thread b acquired lock a.
(priority-donate-tree) Thread b finished.
(priority-donate-tree) Thread d acquired lock c.
(priority-donate-tree) Thread d finished.
(priority-donate-tree) Thread a acquired lock a.
(priority-donate-tree) Thread a finished.
(priority-donate-tree) Thread c acquired lock b.
(priority-donate-tree) Thread c finished.
(priority-donate-tree) Main thread should have priority 31.  Actual priority: 31.
(priority-donate-tree) Threads b, d, a, c should have just finished, in that order.
(priority-donate-tree) end
EOF
pass;