#!/usr/bin/env perl

#
# email-evidence-parser.pl
#   (C) 2012 Jose Miguel Parrella Romero <bureado@cpan.org>
#   This is free software, released under the same terms of Perl.
#
#   Part of the CCSIRT Project.
#

use strict;

use Mail::RBL;
use Email::MIME;
use Email::Received;
use Email::Address;
use Net::Whois::Raw;
use Net::Abuse::Utils qw( :all );

# Configuration
my $list = new Mail::RBL('psbl.surriel.com');

# Operational variables
my @culprits;
my %victims;
my %addresses;
my %enforcers;

# Get the mail in a string
local $/ = undef;
my $string = <>;

# Parse the mail
my $parsed = Email::MIME->new($string);

# Get Received headers
# Scan for RBL listings
for ( $parsed->header('Received') ) {
  my $data = parse_received($_);
  if ( defined($data->{ip}) ) {
    push( @culprits, $data->{ip} );
    print "[DEBUG] Culprit detected as SPAM on a DNSBL. Good Thing(C)\n" if $list->check($data->{ip});
  }
  if ( defined($data->{helo}) ) {
    push( @culprits, $data->{helo} );
    print "[DEBUG] Culprit detected as SPAM on a DNSBL. Good Thing(C)\n" if $list->check($data->{helo});
  }
}

# Get Return-Path and Reply-To Addresses
my @addr_array = Email::Address->parse( $parsed->header('Return-Path') );
push(@addr_array, Email::Address->parse($parsed->header('Reply-To')));

# Get alleged From address (to get domain and identify Abuse Contacts)
my @vctm_array = Email::Address->parse( $parsed->header('From') );

foreach ( @addr_array ) {
  $addresses{$_->address} = 1;
}

foreach ( @vctm_array ) {
  $victims{$_->address} = 1;
}

# Do the WHOIS on Domain Parts of the culprits and addresses
my @abuse_addrs;

foreach ( @culprits ) {
  next if $_ =~ /local$/i;
  my $abuse_info = get_abusenet_contact($_);
  my $whois_info = whois($_);

  my @whois_parts = split("\n", $whois_info);
  my @abuse_parts = grep(/(abuse|abuso|security|seguridad)/i, @whois_parts);

  push ( @abuse_addrs, Email::Address->parse( join(' ', @abuse_parts) . ' ' . $abuse_info ) );
}

foreach ( keys %addresses ) {
  next if $_ =~ /local$/i;
  my $abuse_info = get_abusenet_contact($_);
  my $whois_info = whois($_);

  my @whois_parts = split("\n", $whois_info);
  my @abuse_parts = grep(/(abuse|abuso|security|seguridad)/i, @whois_parts);

  push ( @abuse_addrs, Email::Address->parse( join(' ', @abuse_parts) . ' ' . $abuse_info ) );
}

foreach ( @abuse_addrs ) {
  $enforcers{$_->address} = 1;
}

my @victim_abuse_addrs;

foreach ( keys %victims ) {
  next if $_ =~ /local$/i;
  my $abuse_info = get_abusenet_contact($_);
  my $whois_info = whois($_);

  my @whois_parts = split("\n", $whois_info);
  my @abuse_parts = grep(/(abuse|abuso|security|seguridad)/i, @whois_parts);

  push ( @victim_abuse_addrs, Email::Address->parse( join(' ', @abuse_parts) . ' ' . $abuse_info ) );
}

foreach ( @victim_abuse_addrs ) {
  $victims{$_->address} = 1;
}

#
# Build an e-mail
#

print "\n";
#print "From: ccsirt\@bureado.com\n";
print "To: ", join(',', keys %enforcers) . "\n";
print "Cc: ", join(',', keys %victims) . "\n";
print "Subject: [Crowdsourced CSIRT] SMTP Phishing Activity Detected From the following IP/Hostnames: " . join(' ', @culprits) . "\n";
print "\n";

print "Hi,\n\n";
print "A user has sent us evidence of a potential phishing activity. We'd\n";
print "appreciate your support to investigate and act on the issue. Details\n";
print "follow:\n\n";

print "Affected parties\n";
print join("\n", keys %victims);
print "\n\n";
print "Involved addresses\n";
print join("\n", keys %addresses);
print "\n\n";
print "Alleged culprits\n";
print join("\n", @culprits);
print "\n\n";
print "Probable enforcers\n";
print join("\n", keys %enforcers);
print "\n\n";
print "Thanks!\n";
print "\n\n";

print "Evidence follows:\n";

# Sanitizing BEGINS.
$string =~ s/(Delivered-|X-Original-)?To:\s+(.+)\n/To: recipient\@protect.ed\n/g;
$string =~ s/for [^;]+;/for <recipient\@protect.ed>;/g;
# Sanitizing ENDS.

print $string;