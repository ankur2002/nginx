var fs = require('fs');
var TokenFile = "/etc/nginx/njs/token.txt";
var SessionTokenFile = "/etc/nginx//njs/SessionToken.txt";

function hello(r) {
    r.return(200, "Hello world!");
}

function writeToken(t,file_t) {
    var file = fs.writeFileSync(file_t, t)
}

function readToken(r,f) {
  try{
        fs.accessSync(f, fs.constants.R_OK);
        r.log('readToken: Has READ access : ' + f);
    } catch (e) {
        r.log('readToken: No READ access : ' + f);
        return ("");  // Return empty string if file cannot be read.
    }

    r.log("readToken:" + f)
    var file = fs.readFileSync(f);
    var token = file.toString();
    return (token);
}

function readNonceToken(r) {
    return readToken(r,TokenFile);
}

function readSessionToken(r) {
    return readToken(r,SessionTokenFile);
}

function nonce(r) {
    var token = "";
    r.subrequest('/api_nonce',
      function(res) {
           token = String(res.responseBody).trim();
           r.headersOut['Nonce2'] = token;
           r.headersOut['Nonce'] = res.responseBody;
           writeToken(token,TokenFile);
           r.return(res.status, token);
      });
}


function session(r) {
   var s_token = "";
   r.subrequest('/session_auth', 
       { method: 'POST', 
         body: JSON.stringify({ "principal": "seal", "password": "*******", "nonce": readNonceToken(r) })},
     function(res) {
          r.headersOut['Token'] = readNonceToken(r);
          s_token = res.rawHeadersOut[8][1];
          r.headersOut['Session-Token'] = s_token;
          writeToken(s_token, SessionTokenFile);
          r.return(res.status, s_token);
     });
  return s_token;
}



function nonce2(r) {
        r.subrequest('/api_nonce')
          .then(reply => {
             token = String(reply.responseBody).trim();
             r.headersOut['Nonce2'] = token;
             r.headersOut['Nonce'] = reply.responseBody;
          })
          .then(response => {
            return token;
          })
          .then(session_token => {
            r.subrequest('/auth_nonce',
            { method: 'POST',
              body: {"principal": "seal","password": "********","nonce": r.variables.token }})
                .then(reply => {
                  session_token = reply.responseBody;
                  r.headersOut['Session-Token'] = session_token;
                 })
                .then(response => {
                  r.return(session_token);
                 })
          })
}

export default {hello, nonce, nonce2, session, writeToken, readToken, readSessionToken, readNonceToken} 
