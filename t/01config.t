#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use_ok('Net::Telegram');

my $schema = Net::Telegram->new_from_schema('t/data/schema16.tlc');

my $Config = $schema->call_function('help.getConfig');
