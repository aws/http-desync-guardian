Overview
==========

Testing tenet: 
* **Focus on reviewability.** The test suite must require no knowledge about the library/programming languages but only about HTTP protocol. So it’s easy to review, contribute and re-use.

Feel free to review add test-cases that you think might be valuable in HTTP DeSync prevention.

RFC Definitions
===========

https://tools.ietf.org/html/rfc7230#page-22

* OWS = *( SP / HTAB )
* header-field = field-name ":" OWS field-value OWS
* field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
* field-name = token
* field-value = *( field-content / obs-fold )
* field-vchar = VCHAR / obs-text
* obs-fold = CRLF 1*( SP / HTAB )
* obs-text = %x80-FF
* fragment = <fragment, see [RFC3986], Section 3.5>
* header-field = field-name ":" OWS field-value OWS
* token = 1*tchar
* token          = 1*<any CHAR except CTLs or separators>
* tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
* t-codings = "trailers" / ( transfer-coding [ t-ranking ] )
* t-ranking = OWS ";" OWS "q=" rank
* transfer-coding = "chunked" / "compress" / "deflate" / "gzip" / transfer-extension
* transfer-extension = token *( OWS ";" OWS transfer-parameter )
* transfer-parameter = token BWS "=" BWS ( token / quoted-string )

Format
==========
```yaml
- name: # A human readable description of the test
  uri: # request uri (/foo/bar?baz)
  method: # request method (GET, PUT, POST, etc.)
  version: # http version (e.g. HTTP/1.0 HTTP/1.1, or "" for HTTP/0.9)
  headers: # a list of headers
    - name: "x-my-custom-header\x01" # a header name in quotes
      value: "some value\xff" # value
      tier: # Compliant/NonCompliant/BadHeader
    - name: # as many headers as you need for the test
      value: # ...
      tier: # ...
  expected: # The expected outcome - verdict + critical message parts (if any)
    tier: # Compliant/Acceptable/Ambiguous/Severe request
    reason: # Compliant/EmptyHeader/SuspiciousHeader/NonCompliantHeader/BadHeader/AmbiguousUri/BadUri/NonCompliantVersion/BadVersion/UndefinedContentLengthSemantics/MultipleContentLength/DuplicateContentLength/BadContentLength/UndefinedTransferEncodingSemantics/MultipleTransferEncodingChunked/BadTransferEncoding/BothTeClPresent
    required_message_items: # a list for error message substrings (might be empty)
      - "Content-Length" 
      - "multiple" 
      # From logs we should see why a request was classified as such.
      # E.g. "Contains multiple Content-Length" would match
      # the `required_message_items` above.
```