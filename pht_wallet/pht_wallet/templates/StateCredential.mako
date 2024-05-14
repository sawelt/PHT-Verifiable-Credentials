<h3>State Credential</h3>
<%include file="Credential.mako"/>
% if credential.is_station_emitted():
<div class="emittedBy attribute"><label>Emitted by:</label><span class="value">${credential.emittedBy}</span></div>
% endif
<div class="checksumAlgorithm attribute"><label>Checksum algorithm:</label><span class="value">${credential.checksumAlgorithm}</span></div>
<div class="date attribute"><label>Creation date:</label><span class="value">${str(credential.creationDate)}</span></div>