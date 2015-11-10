use DateTime::Format;
use Digest::HMAC;
use Digest::SHA;
use Base64;
use OpenSSL::RSATools;
use HTTP::Request;

unit class HTTP::Signature;

has $.keyid;
has $.secret;
has $.algorithm = 'hmac-sha256';
has @.headers = <date>;

has $!signing-string;
has $!signature;
has $!authorization_string = 'Signature';

method sign-request( HTTP::Request $request ) {
    #Add a date header if not present
    if !$request.field('date') {
        $request.header.field(:date(strftime( '%a, %d %b %Y %T GMT' ,DateTime.now.utc) ) );
    }

    self!generate_signing_string( $request );
    $!signature = encode-base64( self!sign(), :str );
    $request.header.field( :Authorization( self!format_signature()) );

    return $request;
}

method !sign {
    my $signed;
    given $.algorithm {
        when /hmac\-sha256/ { $signed = hmac($.secret, $!signing-string, &sha256); }
        when /rsa\-sha256/ {
            my $rsa = OpenSSL::RSAKey.new(private-pem => $!secret);
            $signed = $rsa.sign( $!signing-string.encode, :sha256);
        }
    }
    return $signed;
}

method !format_signature {
      my $rv = sprintf(q{%s keyId="%s",algorithm="%s"},
                  $!authorization_string,
                  $.keyid,
                  $.algorithm
               );

      if @.headers.elems == 1 and @.headers[0].lc eq 'date' {
          # if there's only the default header, omit the headers param
      }
      else {
          $rv ~= ",headers=\"@.headers[]\"";
      }

      $rv ~= ", signature=\"$!signature\"";

      return $rv;
  }

method !generate_signing_string( HTTP::Request $request ) {
    $!signing-string = (for @!headers -> $h {
        self!get_header($request,$h);
    }).join("\n");
}

method !get_header ( $req, $name ) {
    if $name eq '(request-target)' {
        return '(request-target): ' ~ $req.method.lc ~ ' ' ~ ( $req.uri.query ?? $req.uri.path ~ '?' ~ $req.uri.query !! $req.uri.path );
    } else {
        return sprintf "%s: %s", $name, $req.field($name).Str;
    }
}
