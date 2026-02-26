@0xfce43831b44a3a13;

struct Header {
  name @0 :Text;
  value @1 :Text;
}

struct AuthRequest {
  method @0 :Text;
  host @1 :Text;
  path @2 :Text;
  query @3 :Text;
  clientIp @4 :Text;
  headers @5 :List(Header);
}

enum DecisionAction {
  pass @0;
  block @1;
  redirect @2;
}

struct AuthDecision {
  action @0 :DecisionAction;
  statusCode @1 :UInt16;
  upstreamValue @2 :Text;
  redirectLocation @3 :Text;
  responseBody @4 :Text;
}

interface ExternalAuthService {
  check @0 (request :AuthRequest) -> (decision :AuthDecision);
}
