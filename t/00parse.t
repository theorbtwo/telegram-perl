#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use_ok('Net::Telegram');

my $schema = Net::Telegram->new_from_schema('t/data/schema16.tlc');

## true/false
is($schema->{'boolFalse#bc799737'}->(), 0);
is($schema->{'boolTrue#997275b5'}->(), 1);

## Vector
# isa_ok($schema->{'vector#1cb5c415'}->( t => 'Int')

## Error
isa_ok($schema->{'error#c4b9f9bb'}->(code => 200, text => 'All ok'), 'Net::Telegram::Error');

## NULL/Undef
is($schema->{'null#56730bcc'}->(), undef);

## help.getConfig
isa_ok($schema->{'help.getConfig#c4f9186b'}->(), 'Config');

## Config
config#2e54dd74 date:int test_mode:Bool this_dc:int dc_options:Vector<DcOption> chat_size_max:int broadcast_size_max:int = Config;

done_testing;
