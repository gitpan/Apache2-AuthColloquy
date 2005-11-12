require 5.005;
use strict;
use ExtUtils::MakeMaker qw(WriteMakefile);

WriteMakefile(
   NAME          => 'Apache2::AuthColloquy',
   VERSION_FROM  => 'lib/Apache2/AuthColloquy.pm',
   ABSTRACT_FROM => 'lib/Apache2/AuthColloquy.pm',
   AUTHOR        => 'Nicola Worthington <nicolaworthington@msn.com>',
   PREREQ_PM     => { 'MD5'  => 0,
                      'Colloquy::Data' => '1.02',
                      'Apache2::Access' => 0,
                      'Apache2::Connection' => 0,
                      'Apache2::Log' => 0,
                      'Apache2::RequestRec' => 0,
                      'Apache2::RequestUtil' => 0,
                      'Apache2::Const' => 0,
                      'mod_perl2' => 0,
                     },
);

