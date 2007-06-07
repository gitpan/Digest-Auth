# -*- perl -*-

# t/001_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'Digest::Auth' ); }

my $object = Digest::Auth->new ();
isa_ok ($object, 'Digest::Auth');


