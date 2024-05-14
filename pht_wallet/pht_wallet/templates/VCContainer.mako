<div class="credential_container">
    <a href="/show_credential?id=${credential.id}">
${credential_renderer(credential)}
    </a>
% if valid:
<img class="checkmark" src="static/ok.svg" />
% endif
</div>