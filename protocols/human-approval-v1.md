# Human approval protocol v1

Transport: root-owned AF_UNIX SOCK_SEQPACKET /run/mano-approval/human.sock.
Caller UID comes only from matching kernel connection/message credentials and
root-owned human.uid mapping. No identity field is accepted in frames.

| Field | View | Confirm |
|---|---|---|
| Version byte |1|1|
| Opcode byte |1|2|
| Approval ID |32 lowercase ASCII hex|32 lowercase ASCII hex|
| Nonce |absent|64 lowercase ASCII hex|
| Operation digest |absent|64 lowercase ASCII hex|
| Password length |absent|2-byte unsigned big-endian UTF8 byte count,1-256|
| Password |absent|exact counted bytes, no NUL|

View length34bytes. Confirm length164+password_length bytes. Extra/missing bytes,
wrong version/opcode, ancillary rights or truncated packets deny. Replies are
bounded128KiB UTF8 JSON version1.0, authenticated as root via message credentials.
Private view comes from the trusted broker. Confirmation requires matching view,
PAM authentication/account policy and a fresh broker single-use decision.
Passwords are never forwarded to the broker control protocol.
