use v6;
use Test;

plan 1;

use HTTP::Signature;
use HTTP::Request;

my $request-str = Q:b (POST /foo?param=value&pet=dog HTTP/1.1\r\nHost: example.com\r\nDate: Thu, 05 Jan 2012 21:31:40 GMT\r\nContent-Type: application/json\r\nContent-MD5: Sd/dVLAcvNLSq16eXua5uQ==\r\nContent-Length: 18\r\n\r\n{"hello": "world"});

my $authorization-header = Q (Signature keyId="Test",algorithm="rsa-sha256",headers="request-line host date content-type content-md5 content-length",signature="NSgN91rEJ7F0W2YjD1iT1FawHJVet2VWctBs7o283TSsPA75kCaUVo2JlnbFqJ5mNs0Dx+mexF1kS/7qaDcS4ht5UXvEG+DDB2x75WuTW62Q6wEVmpxmR92zNkBCMWouN7vB9kbx9BdtUqoeyPEZHH1TMLLrFUBQKt2yR2JKoB8=");

my $public-key = q (
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMIUQ0bDffIaKHL3akONlCGXQLfqs8mP4K99ILz6rbyHEDXrVAU1R3Xf
C4JNRyrRB3aqwF7/aEXJzYMIkmDSHUvvz7pnhQxHsQ5yl91QT0d/eb+Gz4VRHjm4
El4MrUdIUcPxscoPqS/wU8Z8lOi1z7bGMnChiL7WGqnV8h6RrGzJAgMBAAE=
-----END RSA PUBLIC KEY-----
);

#fFrom http://tools.ietf.org/html/draft-cavage-http-signatures-05

my $signer = HTTP::Signature.new(
    secret => $public-key,
);

my $request = HTTP::Request.new;
$request.parse($request-str);
$request.header.field( Authorization => $authorization-header );

$signer.verify-request( $request );
is 1,1, 'OK';
