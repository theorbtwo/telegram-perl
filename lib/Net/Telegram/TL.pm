package Net::Telegram::TL;

use 5.14.2;
# use strictures 1;
# no warnings 'experimental';
use autodie;
use IO::File;
use Data::Printer;
use Try::Tiny;
$|=1;

use Moo;

has 'schema', is => 'rw';

sub parse_tlc {
    my ($self, $tlc_fn) = @_;
    open my $tlc_fh, "<:raw", $tlc_fn;

    $self->schema(read_generic($tlc_fh));
    p $schema;

    return $self;
}
# https://core.telegram.org/mtproto/TL-tl
# 000000 e2 9b 2f 3a 00 00 00 00 27 68 08 54 6d 00 00 00  >../:....'h.Tm...<
#        3a2f9be2    00000000    54086827    0000006d     >../:....'h.Tm...<
#        tls.schema_v2           date
#                    version                 types_num
#         0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
# 000010 86 43 eb 12 ff 9e 65 70 01 23 00 00 00 00 00 00  >.C....ep.#......<
#        12eb4386    70659eff    00002301    00000000     >.C....ep.#......<
#        types:types_num*[tls.Type]
#        tls.type    name:int    '#' - -
# 000020 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  >................<
#        00000000    00000000    00000000    00000000     >................<
# 000030 86 43 eb 12 4e ec c5 9f 05 41 75 64 69 6f 00 00  >.C..N....Audio..<
#        12eb4386    9fc5ec4e    64754105    00006f69     >.C..N....Audio..<


sub read_generic {
    my ($fh) = @_;

    local $/=\4;
    my $constructor_id = unpack 'L<', <$fh>;
    printf "Constructor id: 0x%08x\n", $constructor_id;
    if ($constructor_id == 0x3a2f9be2) {
        # tls.schema_v2#3a2f9be2 version:int date:int types_num:# types:types_num*[ tls.Type ] constructor_num:# constructors:constructor_num*[ tls.Combinator ] functions_num:# functions:functions_num*[ tls.Combinator ] = tls.Schema
        my $schema = {};

        # version:int
        my ($version) = read_int($fh);
        print "Version: $version\n";
        $schema->{version} = $version;

        my ($date) = read_int($fh);
        print "Date: $date=", scalar localtime $date, "\n";
        $schema->{date} = $date;

        my ($types_num) = read_seq($fh);
        print "Number of types: $types_num\n";
        $schema->{types_num} = $types_num;
        
        my @types;
        $schema->{types} = \@types;
        for (0..$types_num-1) {
            #push @types, read_type($fh);
            my $type;
            try {
                $type = read_generic($fh);
            } catch {
                p $schema;
                die "Error reading type";
            };
            push @types, $type;
            $schema->{_types_by_id}{$type->{id}} = $type;
            $schema->{_types_by_name}{$type->{name}} = $type;
        }

        #tls.schema_v2 version:int date:int types_num:# types:types_num*[tls.Type] 
        # constructor_num:# constructors:constructor_num*[tls.Combinator] 

        my ($constructor_num) = read_seq($fh);
        $schema->{constructor_num} = $constructor_num;
        my @constructors;
        $schema->{constructors} = \@constructors;
        for (0..$constructor_num-1) {
            my $constructor;
            try {
                $constructor = read_generic($fh);
            } catch {
                p $schema;
                die "Error reading constructor: ".shift;
            };
            push @constructors, $constructor;
            $schema->{_constructors_by_id}{$constructor->{id}} = $constructor;
            $schema->{_constructors_by_name}{$constructor->{name}} = $constructor;
            push @{$schema->{_types_by_name}{$constructor->{type_name}}{constructors}}, $constructor;
        }

        # functions_num:# functions:functions_num*[tls.Combinator] = tls.Schema;
        my ($functions_num) = read_seq($fh);
        my @functions;
        for (0..$functions_num-1) {
            push @functions, read_generic($fh);
            p $functions[-1];
            $schema->{_functions_by_id}{$functions[-1]{id}} = $functions[-1];
        }
        $schema->{functions} = \@functions;

        return $schema;

    } elsif ($constructor_id == 0x12eb4386) {
        # tls.type#12eb4386 name:int id:string constructors_num:int flags:int arity:int params_type:long = tls.Type
        
        print "read_type\n";
        return read_type($fh);
    } elsif ($constructor_id == 0x5c0a1ed5) {
        # tls.combinator#5c0a1ed5 name:int id:string type_name:int left:tls.CombinatorLeft right:tls.CombinatorRight = tls.Combinator
        # tl-tl.h: TLS_COMBINATOR
        print "read_combinator\n";
        return read_combinator($fh);
    } elsif ($constructor_id == 0x4c12c6d9) {
        # tls.combinatorLeft#4c12c6d9 args_num:# args:args_num*[ tls.Arg ] = tls.CombinatorLeft
        # tl-tl.h: TLS_COMBINATOR_LEFT
        print "read_combinator_left\n";
        return read_combinator_left($fh);
    } elsif ($constructor_id == 0x29dfe61b) {
        # tls.arg#29dfe61b id:string flags:# var_num:flags.1?int exist_var_num:flags.2?int exist_var_bit:flags.2?int type:tls.TypeExpr = tls.Arg
        # tl-tl.h TLS_ARG_V2
        print "read_arg_v2\n";
        return read_arg_v2($fh);
    } elsif ($constructor_id == 0xc1863d08) {
        # tls.typeExpr#c1863d08 name:int flags:int children_num:# children:children_num*[ tls.Expr ] = tls.TypeExpr
        # tl-tl.h TLS_TYPE_EXPR
        print "read_type_expr\n";
        return read_type_expr($fh);
    } elsif ($constructor_id == 0x2c064372) {
        # tls.combinatorRight#2c064372 value:tls.TypeExpr = tls.CombinatorRight
        # ../tg/tl-tl.h:#define TLS_COMBINATOR_RIGHT_V2 0x2c064372
        #tls.combinatorRight value:tls.TypeExpr = tls.CombinatorRight;
        return read_generic($fh);
    } elsif ($constructor_id == 0xecc9da78) {
        # tl-tl.h TLS_EXPR_TYPE 
        # tls.exprType#ecc9da78 _:tls.TypeExpr = tls.Expr
        return read_expr_type($fh);
    } elsif ($constructor_id == 0xcd211f63) {
        # tls.combinatorLeftBuiltin#cd211f63 = tls.CombinatorLeft
        return read_combinator_left_builtin($fh);
    } elsif ($constructor_id == 0x2cecf817) {
        # ???
        return read_type_var($fh);
    } elsif ($constructor_id == 0x70659eff) {
        # ???
        # ../tg/generate.h -- 50:#define NAME_VAR_NUM 0x70659eff
        # ../tg/tl-parser.c -- 2646:  if (!strcmp (t->id, "#")) { t->name = 0x70659eff; return; }
        return read_nat_var($fh);
    } elsif ($constructor_id == 0xd9fb20de) {
        # tls.array#d9fb20de multiplicity:tls.NatExpr args_num:# args:args_num*[ tls.Arg ] = tls.TypeExpr
        # ../tg/tl-tl.h -- 50:#define TLS_ARRAY 0xd9fb20de
        print "read_possibly_array\n";
        # tls.array multiplicity:tls.NatExpr args_num:# args:args_num*[tls.Arg] = tls.TypeExpr;
        my $a = {};
        $a->{multiplicity} = read_generic($fh);
        $a->{args_num} = read_seq($fh);
        $a->{args} = [ map {read_generic($fh)} 1..$a->{args_num} ];
        p $a;
        return $a;

    } elsif ($constructor_id == 0x4e8a14f0) {
        # tls.natVar#4e8a14f0 dif:int var_num:int = tls.NatExpr
        # ../tg/tl-tl.h -- 48:#define TLS_NAT_VAR 0x4e8a14f0
        return read_nat_var($fh);

    } elsif ($constructor_id == 0x0142ceae) {
        # tls.typeVar#0142ceae var_num:int flags:int = tls.TypeExpr
        # ../tg/tl-tl.h -- 49:#define TLS_TYPE_VAR 0x0142ceae
        return read_type_var($fh);

    } elsif ($constructor_id == 0xdcb49bd8) {
        # tl.norm.tl:tls.exprNat#dcb49bd8 _:tls.NatExpr = tls.Expr
        my $x = {};
        $x->{_} = read_generic($fh);
        return $x;
        
    } else {
        die sprintf "Don't know what to do with constructor id 0x%08x", $constructor_id;
    }
}

sub read_nat_var {
    my ($fh) = @_;
    my $nv = {};
    $nv->{dif} = read_int($fh);
    $nv->{var_num} = read_int($fh);
    p $nv;
    return $nv;
}

sub read_type_var {
    my ($fh) = @_;
    #tls.typeVar var_num:int flags:int = tls.TypeExpr;
    my $tv = {};
    $tv->{var_num} = read_int($fh);
    $tv->{flags} = read_int($fh);
    return $tv;
}

sub read_combinator_left_builtin {
    my ($fh) = @_;
    # tls.combinatorLeftBuiltin = tls.CombinatorLeft;
    return;
}

sub read_expr_type {
    my ($fh) = @_;
    # tls.exprType _:tls.TypeExpr = tls.Expr;
    return read_generic($fh);
}

sub read_type_expr {
    my ($fh) = @_;
    my $te = {};
    printf "Need TLS_TYPE_EXPR at offset 0x%x\n", tell($fh);
    #        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    #0012b0 00 00 00 00 08 3d 86 c1 ba 6c 07 22 01 00 00 00  >.....=...l."....<
    #       00000000    c1863d08    22076cba    00000001     >.....=...l."....<
    #0012c0 00 00 00 00 72 43 06 2c 08 3d 86 c1 4e ec c5 9f  >....rC.,.=..N...<
    #       00000000    2c064372    c1863d08    9fc5ec4e     >....rC.,.=..N...<
    #0012d0 00 00 00 00 00 00 00 00 d5 1e 0a 5c 96 64 ac c7  >...........\.d..<
    #       00000000    00000000    5c0a1ed5    c7ac6496     >...........\.d..<

    $te->{name} = read_int($fh);
    $te->{flags} = read_int($fh);
    $te->{children_num} = read_int($fh);
    $te->{children} = [ map {read_generic($fh)} 1..$te->{children_num} ];
    #p $te;
    return $te;
}

sub read_arg_v2 {
    my ($fh) = @_;
    #tls.arg id:string flags:# var_num:flags.1?int exist_var_num:flags.2?int exist_var_bit:flags.2?int type:tls.TypeExpr = tls.Arg;
    my $arg = {};
    say "READING arg:";
    $arg->{id} = read_string($fh);
    say "id: $arg->{id}";
    $arg->{flags} = read_seq($fh);
    say "flags: $arg->{flags}";
    if ($arg->{flags} & (1<<1)) {
        $arg->{var_num} = read_int($fh);
        say "var_num: $arg->{var_num}";
    }
    if ($arg->{flags} & (1<<2)) {
        $arg->{exist_var_num} = read_int($fh);
        say "var_num: $arg->{exist_var_num}";
    }
    if ($arg->{flags} & (1<<2)) {
        $arg->{exist_var_bit} = read_int($fh);
        say "var_num: $arg->{exist_var_bit}";
    }
    $arg->{type} = read_generic($fh);
    say "type: $arg->{type}";
    say "DONE READING arg";

    #p $arg;
    return $arg;
}

sub read_combinator_left {
    my ($fh) = @_;
    #tls.combinatorLeft args_num:# args:args_num*[tls.Arg] = tls.CombinatorLeft;
    my ($left) = {};
    $left->{args_num} = read_seq($fh);
    $left->{args} = [ map {read_generic($fh)} 0..$left->{args_num}-1 ];

    #p $left;
    return $left;
}

sub read_combinator {
    my ($fh) = @_;
    # tls.combinator name:int id:string type_name:int left:tls.CombinatorLeft right:tls.CombinatorRight = tls.Combinator;
    my $comb = {
    };
    $comb->{name} = read_seq($fh);
    $comb->{id}   = read_string($fh);
    $comb->{type_name} = read_seq($fh);
    $comb->{left} = read_generic($fh);
    $comb->{right} = read_generic($fh);
    #p $comb;
    return $comb;
}

sub read_string {
    my ($fh) = @_;
    # len_0 is the first byte of the  length, len is the length of the
    # payload, lenlen is  the number of bytes before  the beginning of
    # the payload (so we can correctly compute the amount of padding)

    local $/ = \1;
    my $len_0 = unpack 'C', <$fh>;
    my ($len, $lenlen);
    if ($len_0 > 253) {
        die "Quite long string ($len_0) not yet supported";
    } else {
        $len = $len_0;
        $lenlen = 1;
    }

    my $str;
    if ($len > 0) {
        local $/ = \$len;
        $str = <$fh>;
        #print "Str: '$str'\n";
    } else {
        $str = '';
    }

    my $padlen = 3-((($len+$lenlen)-1) % 4);
    #print "Padlen: $padlen\n";

    if ($padlen != 0) {
        local $/ = \$padlen;
        my $pad = <$fh>;
        #print "Pad: >$pad<, Padlen: >$padlen<\n";
        die "Confused: padding is not zeros: '$pad'"
            if $pad ne ("\0" x $padlen);
    }

    return $str;
}

# tls.type name:int id:string constructors_num:int flags:int arity:int params_type:long = tls.Type;
sub read_type {
    my ($fh) = @_;
    my $type = {};
    $type->{name} = read_seq($fh);
    printf "Name: 0x%08x\n", $type->{name};
    $type->{id} = read_string($fh);
    $type->{constructors_num} = read_int($fh);
    $type->{flags} = read_int($fh);
    printf "Flags: 0x%x\n", $type->{flags};
    $type->{arity} = read_int($fh);
    $type->{params_type} = read_long($fh);
    #p %$type;

    return $type;
}

sub read_long {
    my ($fh) = @_;
    local $/ = \8;
    return unpack 'Q<', <$fh>;
}

sub read_seq {
    # this is the type called '#' in the schemas.
    my ($fh) = @_;
    local $/ = \4;
    return unpack 'L<', <$fh>;
}

sub read_int {
    my ($fh) = @_;
    local $/ = \4;
    return unpack 'l<', <$fh>;
}

sub find_function {
    my ($self, $name) = @_;

    die "No such function $name" if(!exists $self->schema->{_functions_by_id}{$name});

    return $self->schema->{_functions_by_id}{$name};
}

sub prepare_function {
    my ($self, $function, @args) = @_;

    return sprintf("%s%x = %s", 
                   $function->{id},
                   $function->{name},
                   $self->schema->{_constructors_by_id}{$function->{right}{name}}{id});
}

sub parse_response {
    my ($self, $function, $response) = @_;

    ## turn server result into whatever style of result object $function expects..
}

1;
