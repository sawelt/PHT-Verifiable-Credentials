"""
Notes:
    https://w3c.github.io/vc-jose-cose/
    https://w3c-ccg.github.io/vc-extension-registry/
    https://w3c-ccg.github.io/lds-ed25519-2018/

"""
import base64
import functools
import json
import typing
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from time import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


class Credential:
    def __init__(self, data):
        self.issuer = str(data["issuer"])
        self.id = str(data["id"])
        self.issuanceDate = str(data["issuanceDate"])
        self.subject = data["credentialSubject"]
        self._data = data
        self.subject_id = self.get_subject_description()["id"]

    def get_data(self):
        return self._data

    def get_subject_description(self):
        return self.subject

    def __repr__(self):
        return self.__dict__.__repr__()


class KeyNotFoundError(ValueError):
    pass


class Certificate(Credential):
    def __init__(self, data):
        super().__init__(data)
        self._certified_id_iri = self.get_subject_description()["id"]
        self._name = self.get_subject_description()["name"]
        self._country = self.get_subject_description()["country"]
        self._address = self.get_subject_description()["address"]


class Issuer():
    def __init__(self, iri: str, default_public_key: rsa.RSAPublicKey, is_certificate_authority=False):
        self._iri = iri
        self._default_public_key = default_public_key
        self._keys = {}
        self._is_certificate_authority = is_certificate_authority
        # in a real life application, this would oc not make sense

    def add_key(self, iri: str, public_key: rsa.RSAPublicKey):
        self._keys[iri] = public_key

    def get_key(self, iri: str):
        if iri not in self._keys:
            raise KeyNotFoundError()
        return self._keys[iri]

    def get_default_key(self):
        return self._default_public_key

    def get_iri(self) -> str:
        return self._iri

    def is_certificate_authority(self):
        return self._is_certificate_authority

    def __eq__(self, other):
        if isinstance(other, Issuer):
            return other._iri == self._iri
        raise NotImplementedError()


class IssuerNotInKeyChainError(ValueError):
    pass


"""Keychain singletone"""


class _KeyChain():

    def __init__(self):
        self._issuer_dict: typing.Dict[str, Issuer] = {}

    def getKeyForIssuer(self, issuer_iri: str, key_iri: str = None):
        if issuer_iri not in self._issuer_dict:
            raise IssuerNotInKeyChainError()
        if key_iri is not None:
            return self._issuer_dict[issuer_iri].get_key(key_iri)
        return self._issuer_dict[issuer_iri].get_default_key()

    def add_issuer(self, issuer: Issuer):
        self._issuer_dict[issuer.get_iri()] = issuer

    def __getitem__(self, item):
        try:
            return self._issuer_dict[item]
        except KeyError:
            raise IssuerNotInKeyChainError()

    def __contains__(self, item):
        return item in self._issuer_dict

    def __iter__(self):
        return self._issuer_dict.values().__iter__()


key_chain_inst = _KeyChain()
"""Keychain singleton accessor"""


def KeyChain():
    return key_chain_inst


class Proof:
    def __init__(self, proof_data):
        self._created = proof_data["created"]
        self._verificationMethod = proof_data["verificationMethod"]
        self._proofPurpose = proof_data["proofPurpose"]
        self._proofValue = proof_data["proofValue"]

class StaticAnalysisCredential(Credential):
    def __init__(self, data):
        super().__init__(data)
        self.analysed_train_class = self.get_subject_description()["pht:analysedTrainClass"]
        self.sast_critical = self.get_subject_description()["pht:sast_critical"]
        self.sast_high = self.get_subject_description()["pht:sast_high"]
        self.sast_medium = self.get_subject_description()["pht:sast_medium"]
        self.sast_low = self.get_subject_description()["pht:sast_low"]
        self.secret_detection_critical = self.get_subject_description()["pht:secret_detection_critical"]
        self.secret_detection_high = self.get_subject_description()["pht:secret_detection_high"]
        self.secret_detection_low = self.get_subject_description()["pht:secret_detection_low"]
        self.secret_detection_medium = self.get_subject_description()["pht:secret_detection_medium"]
        self.dependency_scanning_critical = self.get_subject_description()["pht:dependency_scanning_critical"]
        self.dependency_scanning_high = self.get_subject_description()["pht:dependency_scanning_high"]
        self.dependency_scanning_medium = self.get_subject_description()["pht:dependency_scanning_medium"]
        self.dependency_scanning_low = self.get_subject_description()["pht:dependency_scanning_low"]
        self.nlines = self.get_subject_description()["pht:static_nlines"]
        self.vuln_per_line = self.get_subject_description()["pht:static_vuln_per_line"]
        self.static_score = self.get_subject_description()["pht:static_score"]


class TrainCredential(Credential):
    def __init__(self, data):
        super().__init__(data)
        self.label = self.get_subject_description()["label"]
        self.comment = self.get_subject_description()["comment"]
        self.owner_iri = self.get_subject_description()["pht:ownedBy"]
        self.instantiated_from_iri = self.get_subject_description()["pht:instantiatedFrom"]
        self._route_definition_list = self.get_subject_description()["pht:plannedHalt"]

    def get_cleaned_route(self) -> typing.List[str]:
        l = sorted(self._route_definition_list, key=lambda x:x["pht:haltOrder"])
        return [e["pht:haltAtStation"] for e in l]

class StateCredential(Credential):
    def __init__(self, data):
        super().__init__(data)
        self.emittedBy = self.get_subject_description()[
            "pht:emittedBy"] if "pht:emittedBy" in self.get_subject_description() else None
        self.checksumAlgorithm = self.get_subject_description()["pht:checksumAlgorithm"]
        self.checksum = self.get_subject_description()["pht:checksum"]
        self.creationDate = datetime.fromisoformat(self.get_subject_description()["pht:creationDate"])

    def is_station_emitted(self):
        return self.emittedBy is not None


class VisitCredential(Credential):
    def __init__(self, data):
        super().__init__(data)
        self.inputState = self.get_subject_description()["pht:inputState"]
        self.yieldedState = self.get_subject_description()["pht:yieldedState"]
        self.visitedStation = self.get_subject_description()["pht:visitedStation"]
        self.trainVisiting = self.get_subject_description()["pht:trainVisiting"]
        self.visitDate = datetime.fromisoformat(self.get_subject_description()["pht:visitDate"])


class TrainClassCredential(Credential):
    def __init__(self, data):
        super().__init__(data)
        self.label = self.get_subject_description()["label"]
        self.comment = self.get_subject_description()["comment"]
        self.createdBy = self.get_subject_description()["pht:createdBy"]
        self.initialState = self.get_subject_description()["pht:initialState"]
        self.creationDate = self.get_subject_description()["pht:creationDate"]


def parse_credential(data):
    type_ = data["type"]
    if "TrainCredential" in type_:
        return TrainCredential(data)
    if "StateCredential" in type_:
        return StateCredential(data)
    if "VisitCredential" in type_:
        return VisitCredential(data)
    if "TrainClassCredential" in type_:
        return TrainClassCredential(data)
    if "StaticAnalysisCredential" in type_:
        return StaticAnalysisCredential(data)
    return Credential(data)


class JWTVerifiableCredential:
    def __init__(self, jwt_str: str):
        self._jwt_str = jwt_str

    @functools.lru_cache()
    def extract_payload(self):
        base64_payload = self._jwt_str.split(".")[1]
        # fix padding as described in https://stackoverflow.com/a/49459036
        decoded_payload = base64.urlsafe_b64decode(base64_payload + '=' * (-len(base64_payload) % 4))
        return json.loads(decoded_payload)

    @functools.lru_cache()
    def extract_payloaded_credential(self):
        return parse_credential(self.extract_payload()["vc"])

    def get_issuer(self) -> str:
        payload = self.extract_payload()
        return payload["iss"]

    def check_against_keychain(self, keychain: KeyChain):
        issuer = self.get_issuer()
        key = keychain.getKeyForIssuer(issuer)
        return self.check_against_public_key(key)

    def check_against_public_key(self, public_key: rsa.RSAPublicKey):
        try:
            jwt.decode(self._jwt_str, public_key, algorithms=["RS256"])
        except jwt.InvalidTokenError:
            return False
        return True

    def get_jwt_string(self):
        return self._jwt_str

    def __eq__(self, other):
        if isinstance(other, JWTVerifiableCredential):
            return other._jwt_str == self._jwt_str
        if isinstance(other, str):
            return other == self._jwt_str
        raise NotImplementedError()

    def __hash__(self):
        return hash(self._jwt_str)


def create_payload_container(vc: Credential):
    payload_container = dict()
    payload_container["sub"] = vc.subject["id"]
    payload_container["iss"] = vc.issuer
    payload_container["nbf"] = int(time())
    payload_container["jti"] = vc.id
    payload_container["vc"] = vc.get_data()
    return payload_container


def create_jwt(c: Credential, private_key: rsa.RSAPrivateKey):
    return jwt.encode(create_payload_container(c), private_key, algorithm="RS256")


def credentialIssuerFilter(for_issuer: str) -> typing.Callable[[JWTVerifiableCredential], bool]:
    def filter_(c: JWTVerifiableCredential) -> bool:
        return c.get_issuer() == for_issuer

    return filter_


class _CredentialCollection():
    def __init__(self):
        self._vcredentials: typing.Dict[str, JWTVerifiableCredential] = {}
        self._train_vcredentials: typing.Dict[str, typing.Dict[str, JWTVerifiableCredential]] = defaultdict(lambda: {})

    def add_vcredential_contained_in_train(self, vcredential: JWTVerifiableCredential, for_train: str):
        print("Add credential with id:" + vcredential.extract_payloaded_credential().id)
        self._vcredentials[vcredential.extract_payloaded_credential().id] = vcredential
        self._train_vcredentials[for_train][vcredential.extract_payloaded_credential().id] = vcredential

    def get_credentials_for_train(self, for_train: str):
        return self._train_vcredentials[for_train].values() if for_train in self._train_vcredentials else []

    def get_credential_for_train_with_type(self, for_train: str, type_: typing.Union[str, typing.Iterable[str]]) -> \
    typing.List[JWTVerifiableCredential]:
        if for_train not in self._train_vcredentials:
            return []
        type_l = {type_} if isinstance(type_, str) else set(type_)
        print(type_l)
        credential_candidates = self._train_vcredentials[for_train]
        return list(filter(lambda c: c.extract_payloaded_credential().__class__.__name__ in type_l, credential_candidates.values()))

    def get_credential_for_train_issued_by(self, for_train: str, issuer: str) -> typing.List[JWTVerifiableCredential]:
        if for_train not in self._train_vcredentials:
            return []
        credential_candidates = self._train_vcredentials[for_train]
        return list(filter(credentialIssuerFilter(issuer), credential_candidates.values()))

    def get_credential(self, id_: str):
        return self._vcredentials[id_]

    def __getitem__(self, item):
        return self.get_credential(item)


credential_coll_inst = _CredentialCollection()


def CredentialCollection() -> _CredentialCollection:
    return credential_coll_inst
