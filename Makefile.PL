

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME         => 'Digest::Auth',
    VERSION_FROM => 'lib/Digest/Auth.pm', # finds \$VERSION
    AUTHOR       => 'David P Smith (dsmith@Avitar.Net)',
    ABSTRACT     => 'Digest Based Authentication using DBI.',
    PREREQ_PM    => {
                     'Test::Simple' => 0.44,
                    },
);
