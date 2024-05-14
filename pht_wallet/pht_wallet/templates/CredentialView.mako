<html>
<head>
<title>Credential View</title>
<link rel="stylesheet" type="text/css" href="static/style.css">
<link rel="stylesheet" type="text/css" href="static/credential_view.css">
</head>
<body>
<h1>PHT Wallet</h1>
<h2>Credential ${credential.extract_payloaded_credential().id}</h2>
<div id="credential_view_container">
${vcredential_renderer(credential)}
</div>
% if reason_non_validity == 0:
<span id="valid_credential">Signature valid!</span>
% endif
% if reason_non_validity != 0:
<span id="non_valid_credential">Signature not valid:</span>
% endif
% if reason_non_validity == 1:
<span id="reason_non_valid"> Issuer not found in Keychain!</span>
% endif
% if reason_non_validity == 2:
<span id="reason_non_valid"> Key not found for Issuer!</span>
% endif
<div id="issuer_render_container">
    % if credential.extract_payloaded_credential().issuer in keychain:
${issuer_renderer(keychain[credential.extract_payloaded_credential().issuer])}
    %endif
</div>
<label id="jwt_label">
<p id="signed_banner">Signed via JWT:</p>
</label>
<div  id="jwt_string_container">
<textarea rows="10" cols="80" readonly>
${credential.get_jwt_string()}
</textarea>
</div>
<body>
</html>