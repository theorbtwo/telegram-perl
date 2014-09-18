package Net::Telegram;

use strict;
use warnings;

use Moo;

use Net::Telegram::TL;

has 'server', is => 'rw';
has 'tl_schemas', is => 'rw';

sub new_from_schema {
    my ($class, $schema_file) = @_;

    my $tl = Net::Telegram::TL->new->parse_tlc($schema_file);
    my $self = $class->new(tl_schemas => [$tl]);

    return $self;
}

sub add_schema {
    my ($self, $schema) = @_;
    push @{$self->tl_schemas}, $schema;
}


sub call_function {
    my ($self, $function, @args) = @_;

    for my $schema (@{$self->tl_schemas}) {
        my $func = $self->tl_schema->find_function($function);
        next if !$func;
        my $compiled_func = $schema->prepare_function($function, @args);
        my $response = $self->send_call($self->server, $compiled_func);
        my $result = $schema->parse_response($function, $response);
        return $result;
    }

    die "Cannot find function $function in schemata?";

}

1;

