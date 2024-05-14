import typing
import pathlib
from mako.template import Template
from mako.lookup import TemplateLookup
from .credential import *
print("using template lookup path:" + str(pathlib.Path(__file__).parent.absolute()) + "/templates")

lookup = TemplateLookup(directories=[str(pathlib.Path(__file__).parent.absolute()) + "/templates"])

from .credential import Credential

def _render_credential(credential: Credential):
    template_file = credential.__class__.__name__ + ".mako"
    t = lookup.get_template(template_file)
    return t.render(credential=credential)

def _render_vcredential(vcredential: JWTVerifiableCredential):
    credential = vcredential.extract_payloaded_credential()
    try:
        is_valid = vcredential.check_against_keychain(KeyChain())
    except KeyNotFoundError:
        is_valid = False
    except IssuerNotInKeyChainError:
        is_valid = False
    return lookup.get_template("VCContainer.mako").render(credential=credential, valid=is_valid, credential_renderer=_render_credential)

def _render_issuer(issuer: Issuer):
    t = lookup.get_template("Issuer.mako")
    return t.render(issuer=issuer, keychain=KeyChain())

def render_train_credentials(for_train_iri: str):
    main_template = lookup.get_template("CredentialOverview.mako")
    cc = CredentialCollection()
    tc = cc.get_credential_for_train_with_type(for_train_iri, "TrainCredential")[0]
    route = tc.extract_payloaded_credential().get_cleaned_route()
    return main_template.render(credentials=cc,
                                credential_renderer=_render_vcredential,
                                train_iri=for_train_iri,
                                route=route,
                                keychain=KeyChain())

def render_credential_view(credential: JWTVerifiableCredential):
    t = lookup.get_template("CredentialView.mako")
    reason_non_validity = 0
    try:
        credential.check_against_keychain(KeyChain())
    except IssuerNotInKeyChainError:
        reason_non_validity = 1
    except KeyNotFoundError:
        reason_non_validity = 2
    return t.render(credential=credential,
                    vcredential_renderer=_render_vcredential,
                    reason_non_validity=reason_non_validity,
                    keychain=KeyChain(),
                    issuer_renderer=_render_issuer)

def render_train_view(trains: typing.List[str]):
    t = lookup.get_template("TrainOverview.mako")
    return t.render(trains=trains)

def render_keychain_overview():
    t = lookup.get_template("KeychainView.mako")
    return t.render(keychain=KeyChain(), issuer_renderer=_render_issuer)