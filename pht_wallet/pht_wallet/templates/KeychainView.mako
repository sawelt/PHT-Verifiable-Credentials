<html>
<head>
<title>Keychain Overview</title>
<link rel="stylesheet" type="text/css" href="static/style.css">
</head>
<body>
<h1>PHT Wallet</h1>
<h2>Keychain</h2>
<div id="issuer_list">
% for issuer in keychain:
${issuer_renderer(issuer)}
% endfor
</div>
</body>
</html>