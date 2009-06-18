package Digest::HMAC_MD6;

use warnings;
use strict;

use Digest::MD6 qw( md6 md6_hex md6_base64 );

use base qw( Digest::HMAC Exporter );

our @EXPORT_OK = qw( hmac_md6 hmac_md6_hex hmac_md6_base64 );

=head1 NAME

Digest::HMAC_MD6 - MD6 Keyed-Hashing for Message Authentication

=head1 VERSION

This document describes Digest::HMAC_MD6 version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

  use Digest::HMAC_MD6 qw(hmac_md6 hmac_md6_hex);
  $digest = hmac_md6($data, $key);
  print hmac_md6_hex($data, $key);

  # OO style
  use Digest::HMAC_MD6;
  $hmac = Digest::HMAC_MD6->new($key);

  $hmac->add($data);
  $hmac->addfile(*FILE);

  $digest = $hmac->digest;
  $digest = $hmac->hexdigest;
  $digest = $hmac->b64digest;
  
=head1 DESCRIPTION

This module provides HMAC-MD6 hashing.

=head1 INTERFACE 

=head2 C<< new >>

=cut

sub new {
  my ( $class, $key, $block_size, $hash_bits ) = @_;

  $block_size ||= 64;
  local $Digest::MD6::HASH_LENGTH;
  $Digest::MD6::HASH_LENGTH = $hash_bits if defined $hash_bits;

  $key = Digest::MD6->new->add( $key )->digest
   if length( $key ) > $block_size;

  my $self = bless {}, $class;
  $self->{k_ipad} = $key ^ ( chr( 0x36 ) x $block_size );
  $self->{k_opad} = $key ^ ( chr( 0x5c ) x $block_size );
  $self->{hasher} = Digest::MD6->new->add( $self->{k_ipad} );
  $self;
}

### Functional interface

sub hmac_md6 {
  my $data = shift;
  __PACKAGE__->new( @_ )->add( $data )->digest;
}

sub hmac_md6_hex {
  my $data = shift;
  __PACKAGE__->new( @_ )->add( $data )->hexdigest;
}

sub hmac_md6_base64 {
  my $data = shift;
  __PACKAGE__->new( @_ )->add( $data )->b64digest;
}

1;
__END__

=head1 SEE ALSO

L<Digest::HMAC>, L<Digest::MD6>

=head1 DEPENDENCIES

L<Digest::HMAC>, L<Digest::MD6>

=head1 INCOMPATIBILITIES

None reported.

=head1 BUGS AND LIMITATIONS

Please report any bugs or feature requests to
C<bug-digest-hmac_md6@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.

=head1 AUTHOR

Andy Armstrong  C<< <andy@hexten.net> >>

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2009, Andy Armstrong C<< <andy@hexten.net> >>.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.
