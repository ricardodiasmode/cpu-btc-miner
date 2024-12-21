package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw($PREFIX
                  $BINDIR $BINDIR_REL
                  $LIBDIR $LIBDIR_REL
                  $INCLUDEDIR $INCLUDEDIR_REL
                  $APPLINKDIR $APPLINKDIR_REL
                  $ENGINESDIR $ENGINESDIR_REL
                  $MODULESDIR $MODULESDIR_REL
                  $PKGCONFIGDIR $PKGCONFIGDIR_REL
                  $CMAKECONFIGDIR $CMAKECONFIGDIR_REL
                  $VERSION @LDLIBS);

our $PREFIX             = 'C:\Users\ricar\source\repos\btc-miner\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug';
our $BINDIR             = 'C:\Users\ricar\source\repos\btc-miner\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\bin';
our $BINDIR_REL         = 'bin';
our $LIBDIR             = 'C:\Users\ricar\source\repos\btc-miner\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\lib';
our $LIBDIR_REL         = 'lib';
our $INCLUDEDIR         = 'C:\Users\ricar\source\repos\btc-miner\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\include';
our $INCLUDEDIR_REL     = 'include';
our $APPLINKDIR         = 'C:\Users\ricar\source\repos\btc-miner\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\include\openssl';
our $APPLINKDIR_REL     = 'include/openssl';
our $ENGINESDIR         = 'C:\Users\ricar\source\repos\btc-miner\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\lib\engines-3';
our $ENGINESDIR_REL     = 'lib\engines-3';
our $MODULESDIR         = 'C:\Users\ricar\source\repos\btc-miner\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\bin';
our $MODULESDIR_REL     = 'bin';
our $PKGCONFIGDIR       = 'C:\Users\ricar\source\repos\btc-miner\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug';
our $PKGCONFIGDIR_REL   = '.';
our $CMAKECONFIGDIR     = 'C:\Users\ricar\source\repos\btc-miner\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\share\openssl';
our $CMAKECONFIGDIR_REL = 'share\openssl';
our $VERSION            = '3.3.0';
our @LDLIBS             =
    # Unix and Windows use space separation, VMS uses comma separation
    split(/ +| *, */, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ');

1;
