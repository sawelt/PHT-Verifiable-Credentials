<h3>Static Analysis Result Credential</h3>
<%include file="Credential.mako"/>
<div class="attribute"><label>SAST Result (critical/high/medium/low):</label><span class="value">${credential.sast_critical}/${credential.sast_high}/${credential.sast_medium}/${credential.sast_low}</span></div>
<div class="attribute"><label>Secret Detection Result (critical/high/medium/low):</label><span class="value">${credential.secret_detection_critical}/${credential.secret_detection_high}/${credential.secret_detection_medium}/${credential.secret_detection_low}</span></div>
<div class="attribute"><label>Dependency Scanning Result (critical/high/medium/low):</label><span class="value">${credential.dependency_scanning_critical}/${credential.dependency_scanning_high}/${credential.dependency_scanning_medium}/${credential.dependency_scanning_low}</span></div>
<div class="attribute"><label>Number lines:</label><span class="value">${credential.nlines}</span></div>
<div class="attribute"><label>Vulnerability per line:</label><span class="value">${credential.vuln_per_line}</span></div>
<div class="attribute"><label>Static score:</label><span class="value">${credential.static_score}</span></div>