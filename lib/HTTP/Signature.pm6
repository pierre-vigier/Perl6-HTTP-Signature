use DateTime::Format;
use Digest::HMAC;
use Digest::SHA;
use Digest;
use MIME::Base64;
use OpenSSL::RSATools;
use HTTP::Request;

unit class HTTP::Signature;

has $.keyid is rw ;
has $.secret is rw ;
has $.algorithm is rw = 'hmac-sha256';
has @.headers is rw = <date>;

has $!signing-string;
has $!signature;
has $!authorization_string = 'Signature';

my grammar Signature::Grammar {
    token TOP {
        Signature \s+ <keyid> <algorithm> <headers>? <signature>
    }
    token keyid {
        \,? <space>* keyId \= \" $<value>=<-["]>+ \" <space>*
    }
    token algorithm {
        \, <space>* algorithm \= \" $<value>=<-["]>+ \" <space>*
    }
    token headers {
        \, <space>* headers \= \" <header>+ \" <space>*
    }
    token header {
        <space>* $<value>=[<-["]-:space>+]
    }

    token signature {
        \, <space>* signature \= \" $<value>=<-["]>+ \" <space>*
    }
}

method verify-request( HTTP::Request $request ) {
    $!signature = $request.field("Authorization").Str;
    my $match = Signature::Grammar.parse( $!signature );
    $!algorithm = ~$match<algorithm><value>;
    if $match<headers><header> {
        @!headers = $match<headers><header>.flat.map( {~$_<value>} );
    } else {
        @!headers = <date>;
    }
    $!signature = ~$match<signature><value>;
    self!generate_signing_string( $request );

    return self!verify();
}

method sign-request( HTTP::Request $request ) {
    #Add a date header if not present
    if !$request.field('date') {
        $request.header.field(:date(strftime( '%a, %d %b %Y %T GMT' ,DateTime.now.utc) ) );
    }

    self!generate_signing_string( $request );
    $!signature = MIME::Base64.encode( self!sign(), :oneline );
    $request.header.field( :Authorization( self!format_signature()) );

    return $request;
}

method !verify {
    given $.algorithm {
        when /hmac\-sha256/ { return True if MIME::Base64.decode($!signature) == hmac($.secret, $!signing-string, &sha256); }
        when /hmac\-sha1/ { return True if MIME::Base64.decode($!signature) == hmac($.secret, $!signing-string, &sha1); }
        when /hmac\-md5/ { return True if MIME::Base64.decode($!signature) == hmac($.secret, $!signing-string, &md5); }
        when /rsa\-sha256/ {
            my $rsa = OpenSSL::RSAKey.new(public-pem => $!secret);
            return $rsa.verify( ($!signing-string).encode,  MIME::Base64.decode($!signature), :sha256 );
        }
        when /rsa\-sha1/ {
            my $rsa = OpenSSL::RSAKey.new(public-pem => $!secret);
            return $rsa.verify( ($!signing-string).encode,  MIME::Base64.decode($!signature), :sha1 );
        }
        when /rsa\-md5/ {
            my $rsa = OpenSSL::RSAKey.new(public-pem => $!secret);
            return $rsa.verify( ($!signing-string).encode,  MIME::Base64.decode($!signature), :md5 );
        }
    }
    return False;
}
method !sign {
    my $signed;
    given $.algorithm {
        when /hmac\-sha256/ { $signed = hmac($.secret, $!signing-string, &sha256); }
        when /hmac\-sha1/ { $signed = hmac($.secret, $!signing-string, &sha1); }
        when /hmac\-md5/ { $signed = hmac($.secret, $!signing-string, &md5); }
        when /rsa\-sha256/ {
            my $rsa = OpenSSL::RSAKey.new(private-pem => $!secret);
            $signed = $rsa.sign( $!signing-string.encode, :sha256);
        }
        when /rsa\-sha1/ {
            my $rsa = OpenSSL::RSAKey.new(private-pem => $!secret);
            $signed = $rsa.sign( $!signing-string.encode, :sha1);
        }
        when /rsa\-md5/ {
            my $rsa = OpenSSL::RSAKey.new(private-pem => $!secret);
            $signed = $rsa.sign( $!signing-string.encode, :md5);
        }
    }
    return $signed;
}

method !format_signature {
      my $rv = sprintf(q (%s keyId="%s",algorithm="%s"),
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
    } elsif $name eq 'request-line' {
        return 'request-line: ' ~ ( $req.uri.query ?? $req.uri.path ~ '?' ~ $req.uri.query !! $req.uri.path ) ~ ' ' ~ $req.protocol;
    } else {
        return sprintf "%s: %s", $name, $req.field($name).Str;
    }
}
