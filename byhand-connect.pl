#!/usr/bin/perl
use strictures 1;
use feature 'say';
use IO::Async::Loop;
use IO::Async::Socket;
use Time::HiRes 'time';
use feature 'state';
use Data::Printer;
use Math::BigInt;
use Math::Prime::Util::GMP 'factor';

# https://core.telegram.org/mtproto/samples-auth_key

my $loop = IO::Async::Loop->new;
$loop->connect(
               host => '149.154.167.40',
               service => '443',
               socktype => 'stream',

               on_connected => sub {
                 my ($fh) = @_;

                 my $socket = IO::Async::Socket->new(
                                                     handle => $fh,
                                                     on_recv => \&on_recv,
                                                     on_recv_error => sub {
                                                       my ($self, $errno) = @_;
                                                       die "Recv error: $!",
                                                     }
                                                    );
                 $loop->add($socket);
                 # https://core.telegram.org/mtproto/samples-auth_key
                 # my ($raw, $nonce) = req_pq();
                 # hex_dump($raw);

                 # $raw = add_unk_wrapper(0, $raw);
                 # hex_dump($raw);

                 # $raw = add_tcp_wrapper($raw);
                 # hex_dump($raw);

                 # #print "Sending >>>$raw<<<\n";
                 # $socket->send($raw);

                 # dcOption#2ec2a43c id:int hostname:string ip_address:string port:int = DcOption;
                 # config#232d5905 date:int test_mode:Bool this_dc:int dc_options:Vector<DcOption> chat_size_max:int = Config;
                 # ---functions---
                 # help.getConfig#c4f9186b = Config;
                 my $raw = pack('l<', 0xc4f9186b);
                 $raw = add_tcp_wrapper(add_unk_wrapper(0, $raw));
                 $socket->send($raw);
               },
               on_connect_error => sub {
                 die "Connect error: ", join('//', @_);
               },
               on_resolve_error => sub {
                 die "Resolve error: ", join('//', @_);
               }
              );

$loop->run;

sub hex_dump {
  my ($data) = @_;
  my $addr = 0;
  for my $x (split //, $data) {
    if (($addr % 0x10) == 0) {
      print "\n";
      printf "%04x  ", $addr;
    }
    $x = ord $x;
    printf "%02x ", $x;
    $addr++;
  }
  print "\n";
}

sub on_recv {
  my ($self, $dgram, $addr) = @_;

  print "self:  $self\n";
  print "dgram: $dgram\n";
  print "addr:  $addr\n";

  hex_dump($dgram);

  my ($len, $raw) = unpack 'Ca*', $dgram;
  if ($len != length($raw)/4) {
    die "Datagram length doesn't match len of $len";
  }

  hex_dump($raw);
  (my ($key_id, $message_id, $message_len) , $raw) = unpack 'Q<Q<l<a*', $raw;
  print "key_id: $key_id\n";
  print "message_id: $message_id (".scalar localtime($message_id>>32).")\n";
  print "message_len: $message_len\n";
  print "length of raw: ", length($raw), "\n";
  my ($result, $rest) = read_generic($raw);
  p $result;
  hex_dump($rest);

  # Send the acknowledgement out.  We should probably actually wait
  # until we've actually processed the packet for this?

  print "Acking packet\n";
  my $ack = pack('l<3', 0x62d6b459, 1, $message_id);
  $ack = add_unk_wrapper(0, $ack);
  $ack = add_tcp_wrapper($ack);
  $self->send($ack);

  if ($result->{__constructor_tl} =~ m/^resPQ#/) {
    my $pq = $result->{pq};
    $pq = join '', map {sprintf "%02x", ord $_} split //, $result->{pq};
    print "pq, hex: $pq\n";
    $pq = Math::BigInt->new('0x'.$pq);
    print "pq, as_hex: ", $pq->as_hex, "\n";
    my ($p, $q) = factor($pq);
    print "p, q: $p, $q\n";

    
  }
}

sub req_pq {
  my $nonce = join '', map {chr rand 255} 1..16;
  my $raw = pack('l<a*', 0x60469778, $nonce);
  return ($raw, $nonce);
}

sub add_unk_wrapper {
  my ($key_id, $data) = @_;
  print "add_unk_wrapper\n";
  print "key_id: $key_id\n";
  print "data: $data\n";
  my $len = length($data);
  my $raw = pack('q<q<l<a*', $key_id, time * 1<<32, $len, $data);

  return $raw;
}

sub read_generic {
  my ($rest) = @_;

  state $known_constructors = {
                               0+0x5162463 => [
                                               'resPQ#05162463 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector long = ResPQ',
                                               ['nonce', 'int128',
                                                'server_nonce', 'int128',
                                                'pq', 'string',
                                                'server_public_key_fingerprints', 'Vector long'
                                               ]
                                              ],
                               0+0x1cb5c415 => [
                                                'Vector long',
                                                [
                                                 'count', '#',
                                                 'fixme_val', 'long',
                                                ],
                                               ],
                              };
  state $types = {
                  '#'    => {read => sub {
                               unpack('L<a*', shift);
                             }
                            },
                  int128 => {read => sub {
                               unpack('a16a*', shift);
                             }
                            },
                  long   => {read => sub {
                               unpack('Q<a*', shift);
                             }
                            },
                  string => {read => sub {
                               my ($rest) = @_;
                               (my $len_0, $rest) = unpack('Ca*', $rest);
                               my ($len, $lenlen);
                               if ($len_0 <= 253) {
                                 $len = $len_0;
                                 $lenlen = 1;
                               } else {
                                 die "Quite long string ($len_0) not yet supported";
                               }

                               my $str;
                               if ($len > 0) {
                                 ($str, $rest) = unpack("a$len a*", $rest);
                               } else {
                                 $str = '';
                               }

                               my $padlen = 3-((($len+$lenlen)-1) % 4);

                               if ($padlen != 0) {
                                 (my $pad, $rest) = unpack "a$padlen a*", $rest;
                                 if ($pad ne ("\0" x $padlen)) {
                                   die "Confused: padding is not zeros: '$pad'"
                                 }
                               }

                               return ($str, $rest);
                             }
                            },
                  'Vector long' => {read => \&read_generic},
                 };

  (my $constructor_name, $rest) = unpack 'l<a*', $rest;
  if (exists $known_constructors->{$constructor_name}) {
    my ($tl, $parts) = @{$known_constructors->{$constructor_name}};
    #force copy
    $parts = [@$parts];
    my $ret = {};
    $ret->{__constructor_name} = $constructor_name;
    $ret->{__constructor_tl}   = $tl;
    while (@$parts) {
      hex_dump($rest);
      my $name = shift @$parts;
      my $type = shift @$parts;
      if (exists $types->{$type}) {
        ($ret->{$name}, $rest) = $types->{$type}{read}->($rest);
      } else {
        hex_dump $rest;
        die "No types entry for $type";
      }
      p $ret;
    }
    return ($ret, $rest);
  } else {
    p $known_constructors;
    print STDERR sprintf("Don't know what to do with constructor name 0x%08x (%d)\n",
                         $constructor_name, $constructor_name);
    return (undef, $rest);
  }
}

sub add_tcp_wrapper {
  my ($data) = @_;
  return pack('CCa*', 0xEF, length($data)/4, $data);
}
