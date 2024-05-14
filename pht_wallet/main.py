from pht_wallet import *
from cryptography.hazmat.primitives.asymmetric import rsa

import json
import sys
import pathlib
from flask import Flask, request


credential_folder = pathlib.Path("./wallet_store")

keychain = KeyChain()

issuer_pk = {
    "did:example:some_researcher": rsa.generate_private_key(public_exponent=65537,key_size=2048),
    "did:example:trainCreator1": rsa.generate_private_key(public_exponent=65537,key_size=2048),
    "did:example:station_uka_diz": rsa.generate_private_key(public_exponent=65537,key_size=2048),
    "did:example:station_rwth": rsa.generate_private_key(public_exponent=65537,key_size=2048),
    "did:example:station3": rsa.generate_private_key(public_exponent=65537,key_size=2048),
    "did:example:padmeSecurityPipeline": rsa.generate_private_key(public_exponent=65537,key_size=2048),
}

for i in issuer_pk:
    issuer = Issuer(i, issuer_pk[i].public_key())
    keychain.add_issuer(issuer)
# add here pks that should not be trusted per se

issuer_pk["did:example:trainuser2"] = rsa.generate_private_key(public_exponent=65537,key_size=2048)

credentials = CredentialCollection()
trains = []
for train_folder in credential_folder.iterdir():
    for fp in train_folder.iterdir():
        print("Read credential:" + str(fp))
        with open(fp,"r") as f:
            data = json.load(f)
            c = parse_credential(data)
            print("Create jwt with issuer:" + c.issuer)
            jwt = create_jwt(c, issuer_pk[c.issuer])

            jwtc = JWTVerifiableCredential(jwt)
            credentials.add_vcredential_contained_in_train(jwtc, str(train_folder.name))
    trains.append(str(train_folder.name))


app = Flask(__name__)

@app.get("/trainview")
def c():
    return render_train_credentials(str(request.args.get("id")))

@app.get("/trains")
def t():
    return render_train_view(trains)

@app.get("/show_credential")
def credential_overview():
    return render_credential_view(credentials[str(request.args.get("id"))])

@app.get("/keychain")
def keychain_overview():
    return render_keychain_overview()