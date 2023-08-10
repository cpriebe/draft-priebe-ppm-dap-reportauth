---
###
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is "draft-<yourname>-<workgroup>-<name>.md".
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
title: "Report authentication for PPM DAP"
category: info

docname: draft-priebe-ppm-dap-reportauth-latest
submissiontype: IETF
number:
date:
consensus: false
v: 0
area: "Security"
workgroup: "Privacy Preserving Measurement"
keyword:
 - authentication
 - rate limiting
 - privacy preserving measurement
 - distributed aggregation protocol
venue:
  group: "Privacy Preserving Measurement"
  type: "Working Group"
  mail: "ppm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/ppm/"
  github: "cpriebe/draft-priebe-ppm-dap-reportauth"
  latest: "https://cpriebe.github.io/draft-priebe-ppm-dap-reportauth/draft-priebe-ppm-dap-reportauth.html"

author:
 -
    fullname: Christian Priebe
    organization: Apple Inc.
    email: "cpriebe@apple.com"
 -
    fullname: Linmao Song
    organization: Apple Inc.
    email: "linmao_song@apple.com"

normative:

informative:


--- abstract
This document describes an upload extension to the Distributed
Aggregation Protocol for Privacy Preserving Measurement
{{!DAP=I-D.draft-ietf-ppm-dap-04}}. The extension contains a Privacy
Pass token as defined in
{{!PPARCH=I-D.draft-ietf-privacypass-architecture-13}}, which allows
Aggregators to verify a DAP report is from a client which has been
authenticated and optionally rate-limited, without learning the client's
identity, to protect against Sybil attacks.


--- middle

# Introduction

The Distributed Aggregation Protocol for Privacy Preserving Measurement
{{!DAP}} defines a multi-party distributed aggregation protocol that
allows measuring sensitive user data on a collective level, without
revealing any individual participant's identity or data.

The anonymous nature of the data upload comes with the risk of Sybil
Attacks. A malicious party may generate a large number of reports, then
upload them to the aggregators to skew aggregation results in order to
reveal information about honest measurements (privacy violation), or to
influence results to their benefit ("stats poisoning"). Client
authentication and rate limiting can be used to throttle such attacks.
However, authentication and effective rate limiting requires associating
an upload with a client identity, and thus defeats the purpose of
{{!DAP}}.

Privacy Pass tokens as defined in {{!PPARCH}} offer a framework to solve
this dilemma. In this protocol, a client can go through a token issuance
process to generate unlinkable one-time use authentication tokens. By
presenting the token to a service provider (i.e. the Origin, as defined
in {{!PPARCH}}), a client can prove to have been authenticated by an
Attester that the service provider trusts, without revealing its
identity to the latter.

This document provides the specification for a {{!DAP}} upload report
extension that leverages Privacy Pass tokens to mitigate the Sybil
attack risk in {{!DAP}} uploads. For this, Clients request a fixed
number of tokens for each Aggregator it sends report shares to within
each token issuance window. Token issuance follows the process outlined
in {{!PPISSUANCE=I-D.ietf-privacypass-protocol}}. As part of this
process, the Client is authenticated by the Attester. When a Client
contributes to a measurement task, it adds a token for each Aggregator
to the corresponding encrypted input share within the report.

Rate-Limited Privacy Pass tokens
{{!RATE-LIMITED=I-D.draft-ietf-privacypass-rate-limit-tokens-01}}
provide further protection against Sybil attacks by introducing an
issuance protocol in which token requests are rate-limited by the
Attester according to the policy defined by the Issuer which issues
tokens as defined in {{!PPARCH}}. While it is RECOMMENDED to use
rate-limited tokens to prevent authenticated Clients from launching
Sybil attacks, the DAP extension described in this document is
compatible with any type of Privacy Pass tokens. Non-rate-limited tokens
can be sufficient if authenticated clients are assumed to not launch
Sybil attacks.

Aggregators that opt-in to support this extension fulfill the role of
Origins as defined in {{!PPARCH}}. When an Aggregator receives an input
share, it validates the token by verifying the token signature using the
public Token Key from the Issuer as outlined in
{{!PPAUTHSCHEME=I-D.ietf-privacypass-auth-scheme}}. It also verifies that
the token nonce has not been seen for the current task to prevent double
spending. Upon successful validation which proves to the Aggregator that
the Client has been authenticated and optionally rate-limited, the
Aggregator can process the report share as outlined in {{!DAP}}.

This document does not specify the coordination between Aggregators and
Issuers to exchange Token Keys used for validating token signatures or
to configure the Issuer rate-limiting policy. This is assumed to be done
out-of-band.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the same conventions for error handling as {{!DAP}}.
In addition, this document extends the core specification by adding the
following error type:

| Type                  | Description                               |
|:----------------------|:------------------------------------------|
| unauthenticatedReport | An Aggregator has failed to validate the  |
|                       | input share token or no token was         |
|                       | provided                                  |

> TODO: This should be a new PrepareError variant, rather than a new
> error type URI, see
> https://github.com/cpriebe/draft-priebe-ppm-dap-reportauth/issues/8

The terms used follow the definitions in {{!DAP}} and {{!PPARCH}}. In
addition, the following terms are used throughout this document:

Token:
: A Privacy Pass Token as defined in {{!PPARCH}} included in upload
report shares to prove that the client has been authenticated and
optionally rate-limited.

# The ReportAuth extension

## Overview

The ReportAuth extension encapsulates a token allowing a Client to prove
to Aggregators (Leader and Helpers) that it has been authenticated and
optionally rate-limited without revealing its identity when uploading a
report. The token's lifecycle can be divided into three stages. First,
the client follows the {{!PPISSUANCE}} protocol to obtain a certain
number of Aggregator-specific tokens.  Second, at the time of upload,
the client includes the tokens in ReportAuth extensions within each
Aggregator's input share. Third, the aggregators redeem the tokens as
outlined in {{!PPAUTHSCHEME}}, as part of their aggregation
initialization.  {{fig-interaction-overview}} shows an overview of the
involved parties and their interactions.

~~~
+---------+   +-----------+    +---------+    +--------+      +--------+
| Client  |   | Attester  |    | Issuer  |    | Leader |      | Helper |
+---------+   +-----------+    +---------+    +--------+      +--------+
     |              |               |             |               |
<per Aggregator>
[Challenge]-------->|               |             |               |
     |     <authenticate Client>    |             |               |
     |              |--[Challenge]->|             |               |
     |              |<----[Token]---|             |               |
     |    [<enforce rate limit>]    |             |               |
     |<---[Token]---|               |             |               |
     |              |               |             |               |
     |              |               |             |               |
<upon upload>
     |          [payload + tokens      ]          |               |
     |----------[within input share    ]--------->|               |
     |          [Report Auth extensions]          |               |
     |              |               |    <validate Leader token>  |
     |              |               |             | [Helper    ]  |
     |              |               |             |-[share with]->|
     |              |               |             | [ReportAuth]  |
     |              |               |             | [extension ]  |
     |              |               |             |     <validate token>
~~~
{: #fig-interaction-overview title="Interaction overview"}

## Extension definition

The ReportAuth extension contains two elements:

- A Privacy Pass token obtained from an Issuer of the {{!PPARCH}}
  architecture. By checking the token's validity, an Aggregator can verify
  the uploading client has been authenticated. In case rate-limited token
  issuance as described in {{!RATE-LIMITED}} is used, this also verifies
  that the payload is within a rate limit configured in the Issuer.
- The challenge originally used by the client to obtain the token. This
  is to allow the Aggregator to reconstruct the context necessary for the
  token validation. In the standard {{!PPARCH}} architecture, the challenge
  is sent by the Origin, or Aggregator in the case of DAP, to the Client.
  In this extension's use case, the challenge is synthesized by the
  Client. This removes the requirement for the initial challenge-response
  between the Client and the Aggregators.


The ReportAuth extension is structured as follows:

~~~
struct {
    Token token;
    Challenge challenge;
} ReportAuth;

struct {
    uint16_t token_type;
    uint8_t nonce[32];
    uint8_t challenge_digest[32];
    uint8_t token_key_id[Nid];
    uint8_t authenticator[Nk];
} Token; // as defined in [PPAUTHSCHEME], Section 2.2

struct {
    uint16_t token_type;
    opaque issuer_name<1..2^16-1>;
    opaque redemption_context<0..32>;
    opaque origin_info<0..2^16-1>;
} Challenge; // as defined in [PPAUTHSCHEME], Section 2.1
~~~

The ReportAuth extension's fields' values are as follows:

~~~
+----------------+--------------------+-------------------------+------+
| field          | subfield           | Value                   | Note |
+----------------+--------------------+-------------------------+------+
+----------------+--------------------+-------------------------+------+
| Token          | token_type         |                         | [1]  |
+----------------+--------------------+-------------------------+------+
|                | nonce              | See "Setting the        |      |
|                |                    | report ID"              | [1]  |
+----------------+--------------------+-------------------------+------+
|                | challenge_digest   |                         | [1]  |
+----------------+--------------------+-------------------------+------+
|                | token_key_id       |                         | [1]  |
+----------------+--------------------+-------------------------+------+
|                | authenticator      |                         | [1]  |
+----------------+--------------------+-------------------------+------+
| Challenge      |...                 | See "Token Aquisition"  |      |
+----------------+--------------------+-------------------------+------+
~~~

\[1\] See {{!PPAUTHSCHEME}}

The challenge synthesis, token acquisition, and report creation are
discussed in detail in the following section. The token redemption is
discussed in {{aggregator-behavior}}.

# Client behavior

## Challenge synthesis

The generation of the challenge is implementation specific. An
implementation MAY choose to let Aggregators deliver the challenge to
the clients, or it may let the client synthesize the challenge as
follows:

~~~
+--------------------+--------------------------------------+
| subfield           | Value                                |
+--------------------+--------------------------------------+
| issuer_name        | host name of the Issuer              |
+--------------------+--------------------------------------+
| redemption_context | empty if synthesized by the client,  |
|                    | set by the Aggregator otherwise      |
+--------------------+--------------------------------------+
| origin_info        | host name of the Aggregator          |
+--------------------+--------------------------------------+
~~~

If the client synthesizes the challenge, the redemption_context field
SHOULD be empty.

## Token acquisition {#token-acquisition}

The Client includes the per-Aggregator challenge in token issuance
requests to the {{!PPARCH}} infrastructure. The client MUST obtain a
fixed number of tokens per Aggregator, at a time not associated with the
{{!DAP}} upload. This can be at random times, or at fixed intervals, as
long as the acquisition time cannot be linked to a specific {{!DAP}}
upload. This disassociation is important to mitigate timing attacks. See
{{timing-token-issuance}} for security considerations on this.

## Report creation

{{fig-reportauth-extension}} shows an overview of the DAP report
structure. This extension (ReportAuth) is added to the upload extensions
section of each Aggregator's input share in the upload report, as
defined in {{!DAP, Section 4.3.3}}.

~~~
+-----------------------------------------------------------+
| Report                                                    |
+--+-----------------------------------------------------+--+
|  | ReportMetadata                                      |  |
|  +--+-----------------------------------------------+--+  |
|  |  | report_id                                     |  |  |
|  |  +-----------------------------------------------+  |  |
|  |  | ...                                           |  |  |
|  +--+-----------------------------------------------+--+  |
|  | PublicShare                                         |  |
|  +-----------------------------------------------------+  |
|  | HpkeCiphertext (encrypted_input_share)              |  |
|  |(per aggregator)                                     |  |
|  +--+-----------------------------------------------+--+  |
|  |  | PlainTextInputShare                           |  |  |
|  +--+--+-----------------------------------------+--+--+  |
|  |  |  | Extensions                              |  |  |  |
|  +--+--+--+-----------------------------------+--+--+--+  |
|  |  |  |  | Extension                         |  |  |  |  |
|  |  +--+--+--+-----------------------------+--+--+--+--+  |
|  |  |  |  |  | extension_type = ReportAuth |  |  |  |  |  |
|  |  +--+--+--+-----------------------------+--+--+--+--+  |
|  |  |  |  |  | ReportAuth extension        |  |  |  |  |  |
|  |  +--+--+--+-----------------------------+--+--+--+--+  |
|  |  |  |  | ...                               |  |  |  |  |
|  |  +--+--+-----------------------------------+--+--+--+  |
|  |  |  | Payload                                 |  |  |  |
+--+--+--+-----------------------------------------+--+--+--+
~~~
{: #fig-reportauth-extension title="ReportAuth extension within a DAP report"}

Note that there is currently no defined extension type for this
extension yet, see {{iana-considerations}}.

### Constructing the ReportAuth extension

At the time of upload, the Client selects tokens for each of the
Aggregators. The Client MUST NOT reuse a token previously used for the
same task. However, the client MAY re-use tokens for a different task.
If the client has no unused token left or the client has not obtained
tokens for a participating Aggregator, it MUST abort the upload.

> TOOO: Add a security consideration section on reuse of tokens across
> tasks, in particular in combination with the proposed optimisation in
> the following section to reuse token nonces as report IDs. Reuse of
> tokens and report IDs allows correlating the corresponding reports.

The client uses the allocated token, and the token's
challenge, to construct the ReportAuth extension and include it
in the PlaintextInputShare, as specified in {{!DAP, Section 4.3.2}}. The
process is repeated for each Aggregator's input share.

### Setting the report ID {#setting-report-id}

As per {{!DAP, Section 4.3.2}} The report ID MUST be generated using a
cryptographically secure random number generator.

As per {{!PPAUTHSCHEME, Section 2.2}}, the token nonce is a
randomly-generated 32-byte value. As an optimisation, a DAP deployment
MAY require clients to re-use the lower 16 bytes of the nonce of the
token embedded in the ReportAuth extension as the {{!DAP}} report's ID.
This allows Aggregators to make sure each token is only used once per
task by verifying that token nonce and report ID are the same and
leveraging the anti-reply mechanism specified in {{!DAP, Section 4.3.2
and Section 4.4.1.4}} step 6.

Note that in this case clients MUST manage token sets containing one
token per Aggregator with a shared nonce.

# Aggregator behavior {#aggregator-behavior}

Aggregators that opt-in to support this extension and are configured to
enforce it for a given task, MUST reject reports not containing the
extension. Equally, if they do not recognize or support the extension,
they MUST reject reports containing the extension.

In case the Aggregator is configured to support it, an additional step
is added to the Input Share Preparation in {{!DAP, Section 4.4.1.5}}.
Specifically, both the Leader and Helpers MUST perform the following:

- Extract the token and the challenge from the upload extension within
  their respective ReportShare.
- Validate the origin_info field of the challenge contains the
  aggregator's hostname.
- Validate the token, as per {{!PPISSUANCE, Section 6.4}}. This
  includes verifying the token is issued with an active Issuer Token
  Key.
- Validate that the token has not previously been used for the current
  task to mitigate against replay attacks. If clients have been
  instructed to reuse token nonces as report IDs (see
  {{setting-report-id}}), this can be achieved by validating
  `token.nonce[16...31] == report.metadata.report_id`. Otherwise, token
  nonce reuse MUST be tracked independently of report ID reuse.

If any of the above steps fails, the aggregator MUST reject the report
share with an "unauthenticatedReport" error. Note that the binding of
report and token nonce is an optimisation, allowing aggregators to only
keep track of one set of nonces. Aggregators MAY choose to additionally
verify and keep track of the full token nonce.

# Security Considerations {#security-considerations}

## Threat model

{{!PPARCH, Section 4}} defines different deployment models in which
Attester, Issuer, and Origin can be run by the same or by different
parties. The threat model for this extension assumes that at least
Attester and Issuer are run by different parties to avoid
de-anonymization attacks in which unique Issuer Token Keys could be used
to sign tokens for a targeted client. However, this threat model assumes
that the Attester and a subset of Aggregators, and Issuer and a subset
of Aggregators might be run by the same entity.

No single party should be able to associate the identity of a client
with a specific uploaded report nor learn which measurement task a given
client is contributing to.

## Timing and frequency of token issuance requests {#timing-token-issuance}

As discussed in {{token-acquisition}} token issuance MUST be independent
of token redemption. If clients requested tokens only in response to
receiving instructions to contribute to a measurement task, an Attester
would be able to infer which task a given client has contributed to
based on the timing of the token issuance request.

Equally, the frequency and number of token issuance requests MUST be
independent of token redemption and the timing of instructions for task
contributions. Clients MUST request tokens with a fixed frequency, e.g.
a fixed number of tokens each day. This is to prevent an Attester from
inferring which task a client has contributed to based on the number of
token issuance requests.

## Challenge synthesis

It is assumed that challenges are synthesized by the client with an
empty redemption_context. However, adopters MAY require clients to
obtain challenges from Aggregators directly. In this case, the timing
and frequency considerations above equally apply to challenge requests.
Furthermore, clients MUST ensure that they don't reveal their identity
to the Aggregators e.g. by making challenge requests via an Oblivious
HTTP {{!OHTTP=I-D.draft-ietf-ohai-ohttp-08}} proxy. Otherwise, a
malicious Aggregator might issue a challenge with a unique
redemption_context that would allow it to associate upload reports with
client identities at token redemption time.

## Token Key and Issuer Origin Secret rotation with rate-limited tokens {#issuer-key-rotation}

In case the {{!RATE-LIMITED}} issuance protocol is used, Issuers MUST
periodically rotate the per-Origin Token Key and Issuer Origin Secret
values as described in {{!RATE-LIMITED, Section 10.1}} to prevent
malicious clients from hoarding tokens across Issuer policy windows in
order to bypass rate limiting. While Aggregators must accommodate for
this key rotation and SHOULD accept tokens signed with the private key
associated with Token Keys older than the most recent key, they SHOULD
limit the time window during which such tokens are accepted.

## Compromised parties and collusion

This section discusses the implications of compromise of the parties
involved in the protocol as well as collusion between them. Note that
these considerations differ significantly depending on whether
authenticated clients are assumed to be trusted or not. In the case
authenticated clients are assumed to potentially act maliciously, it is
assumed a rate-limiting issuance protocol as described in
{{!RATE-LIMITED}} is used.

### Malicious Client

A malicious Client may attempt to generate and upload a large number of
reports to skew aggregation results in order to reveal information about
honest measurements (privacy violation), or to influence results to
their benefit ("stats poisoning"). However, as Aggregators reject input
shares without authentication tokens, with tokens that have already been
redeemed for the same task, or with tokens that are otherwise invalid,
Clients are limited to a number of reports within the rate limit
configured at the Issuer. The rate limit should be configured so that
it is impossible to skew aggregation results by individual Clients or a
small number of colluding Clients.

A malicious Client may attempt to hoard tokens across policy windows to
bypass the rate limit. This is mitigated by the periodic Token Key and
Issuer Origin Secret rotation discussed in {{issuer-key-rotation}}.

### Malicious Attester

A malicious Attester can choose not to authenticate clients or enforce
rate limits and allow (selected) malicious Clients to contribute an
arbitrary number of reports to one or more collections. This could lead
to stats poisoning (within the limits enforced by the VDAF). However, a
malicious Attester alone is not able to learn which task a given client
is contributing to.

### Malicious Issuer

A compromised Issuer can generate an arbitrary amount of tokens. As with
a compromised Attester that doesn't enforce rate limits, this could
allow malicious clients to contribute an arbitrary number of reports to
one or more collections to achieve stats poisoning. The Issuer never
learns the identities of clients.

### Malicious Aggregator

A malicious Aggregator, e.g. Leader, could decide not to authenticate by
validating the ReportAuth token in upload reports. However, the
corresponding upload shares of the other Aggregators sent by a malicious
colluding client would fail validation. A malicious Leader could decide
to inject additional reports but Helper shares would fail validation
without valid rate-limited tokens.

> TODO: Address the impact of Leaders dropping reports

### Collusion between Attester and Leader

It is important to prevent the Leader from identifying individual
clients to avoid de-anonymization attacks in which the Leader isolates
an upload report from a victim and injects reports with zero'd vectors.
The Helper is meant to prevent such malicious Leader injections by
validating the token included in the Helper share. However, since the
Leader and Attester collude, it is possible for the Leader to obtain an
arbitrary number of valid Helper tokens to mount such an attack.

To prevent the Leader from targeting individual Clients it is therefore
required that Clients communicate with the Leader in a
privacy-preserving fashion, e.g. via Oblivious HTTP {{!OHTTP}}, so the
Leader cannot identify the origin of a report itself.

### Collusion between Issuer and Helper

Issuer and Helper might be run by the same party or decide to collude.
Neither Issuer nor Helper know the identity of clients that tokens are
issued or redeemed for so that targeted attacks aren't possible by
either or both of them. The risks should be equivalent to those of a
compromised Issuer.

# IANA Considerations {#iana-considerations}

> TODO: Assign extension type identifier

--- back

# Contributors
{:numbered="false"}

Christopher Patton
Cloudflare
cpatton@cloudflare.com

Tommy Pauly
Apple Inc.
tpauly@apple.com

Kunal Talwar
Apple Inc.
ktalwar@apple.com

Shan Wang
Apple Inc.
shan_wang@apple.com

Christopher A. Wood
Cloudflare
caw@heapingbits.net

