<html>
<head>
<title>Train Overview</title>
<link rel="stylesheet" type="text/css" href="static/style.css">
</head>
<body>
<h1>PHT Wallet</h1>
<h2>Trains</h2>
<ul class="trainlist">
% for train in trains:
<a href="/trainview?id=${train}">
<li class="trainitem">${train}</li>
</a>
% endfor
</ul>
</body>
</html>