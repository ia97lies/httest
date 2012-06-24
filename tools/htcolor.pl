#!/usr/bin/perl
#
# colors httest output, just pipe into this script and see...
#
while (<STDIN>) {
    my $line = $_;
    chomp($line);
    if ($line =~ m/^>/) {
      # CLIENT: dark blue
      print "\033[1;34m$line\033[0m\n";
    } elsif ($line =~ m/^</) {
      # CLIENT: light blue
      print "\033[0;34m$line\033[0m\n";
    } elsif ($line =~ m/^ {24,24}>/) {
      # SERVER: dark green
      print "\033[1;32m$line\033[0m\n";
    } elsif ($line =~ m/^ {24,24}</) {
      #  SERVER: light green
      print "\033[0;32m$line\033[0m\n";
    } elsif ($line =~ m/^ {48,48}>/) {
      # SERVER 2: dark purple
      print "\033[1;35m$line\033[0m\n";
    } elsif ($line =~ m/^ {48,48}</) {
      # SERVER 2: light purple
      print "\033[0;35m$line\033[0m\n";
    } elsif ($line =~ m/^ +>/) {
      # SERVER X: dark brown
      print "\033[1;33m$line\033[0m\n";
    } elsif ($line =~ m/^ +</) {
      # SERVER X: light brown
      print "\033[0;33m$line\033[0m\n";
    } elsif ($line =~ m/^ *\_[_-]/) {
      # data: black
      print "$line\n";
    } elsif ($line =~ m/^ *[A-Z_][A-Z_:]*[ \t]/) {
      # command: black (keyword bold)
      $line =~ m/[A-Z_][A-Z_:]*[ \t]/g;
      $line =~ s/$&/\033[1m$&\033[0m/;
      print "$line\n";
    } else {
      # rest: black
      print "$line\n";
    }
  }
