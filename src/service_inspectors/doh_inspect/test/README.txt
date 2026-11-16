DoH inspector test capture
=========================

doh_inspect.pcap contains two HTTP/1.1 DoH transactions:

  1. GET /dns-query?dns=<base64url> with a DNS query for example.com
  2. POST /dns-query with Content-Type application/dns-message and a DNS
     query for dns.google

Both requests have application/dns-message responses. The capture is intended
for use with a configuration that binds port 80 to http_inspect and enables
doh_inspect:

    http_inspect = {}
    doh_inspect = {}

    binder = {
        { when = { proto = 'tcp', ports = '80', role = 'server' },
          use = { type = 'http_inspect' } }
    }

Expected doh_inspect peg counts after processing the capture:

    requests = 2
    responses = 2
    get_requests = 1
    post_requests = 1
    domains = 2

Enable DoH trace to see the extracted domains:

    trace = { modules = { doh_inspect = { all = 1 } } }
