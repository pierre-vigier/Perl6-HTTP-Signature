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
    $!signature.say;
    my $match = Signature::Grammar.parse( $!signature );
    ($match<keyid><value> , $match<algorithm><value> , $match<signature><value>).join(' | ').say;
    for $match<headers><header>.flat -> $h {
        say ~$h<value>;
    }
    $!algorithm = ~$match<algorithm><value>;
    @!headers = $match<headers><header>.flat.map( {~$_<value>} );
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
    $!signature = encode-base64( self!sign(), :str );
    $request.header.field( :Authorization( self!format_signature()) );

    return $request;
}

method !verify {
    given $.algorithm {
        when /hmac\-sha256/ { return True if $!signature eq hmac($.secret, $!signing-string, &sha256); }
        when /rsa\-sha256/ {
            my $rsa = OpenSSL::RSAKey.new(public-pem => $!secret);
            return $rsa.verify( $!signing-string.encode, decode-base64($!signature, :buf) );
        }
    }
    return False;
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
        say( "check header $h ");
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
