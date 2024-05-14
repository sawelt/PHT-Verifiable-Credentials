<div class="issuer_container">
<h3>Issuer: ${issuer.get_iri()}</h3>
<label class="public_key_label">Public key:</label>
<textarea class="public_key" rows="10" cols="80" readonly>
${issuer.get_default_key().public_numbers().n}
</textarea>
</div>