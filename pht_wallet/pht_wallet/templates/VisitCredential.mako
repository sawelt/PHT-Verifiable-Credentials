<h3>Visit Credential</h3>
<%include file="Credential.mako"/>
<div class="attribute"><label>Train visiting:</label><span class="value">${credential.trainVisiting}</span></div>
<div class="attribute"><label>Station visited:</label><span class="value">${credential.visitedStation}</span></div>
<div class="attribute"><label>Input state:</label><span class="value">${credential.inputState}</span></div>
<div class="attribute"><label>Yielded state:</label><span class="value">${credential.yieldedState}</span></div>
<div class="date attribute"><label>Date of visit:</label><span class="value">${str(credential.visitDate)}</span></div>