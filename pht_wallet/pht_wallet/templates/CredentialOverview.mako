<html>
<head>
<title>PHT Wallet</title>
<link rel="stylesheet" type="text/css" href="static/style.css">
</head>
<body>
<h1>PHT wallet</h1>
<h2>Train: ${train_iri}</h2>
<p class="credential_section">General</p>
<div class="credential_collection">
% for credential in credentials.get_credential_for_train_with_type(train_iri, ["TrainCredential","TrainClassCredential", "StaticAnalysisCredential"]):
${credential_renderer(credential)}
% endfor
</div>
% for station_iri in route:
<p class="credential_section">${station_iri}</p>
<div class="credential_collection">
% for credential in credentials.get_credential_for_train_issued_by(train_iri, station_iri):
${credential_renderer(credential)}
% endfor
</div>
% endfor
</body>
</html>