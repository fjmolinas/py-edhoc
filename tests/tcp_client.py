import logging
import pickle
import socket
from binascii import unhexlify

import cbor2
from cose import OKP, CoseEllipticCurves, CoseAlgorithms, CoseHeaderKeys

from edhoc.definitions import Correlation, Method, CipherSuite
from edhoc.roles.edhoc import CoseHeaderMap
from edhoc.roles.initiator import Initiator

logging.basicConfig(level=logging.INFO)

# private signature key
private_key = OKP(
    crv=CoseEllipticCurves.ED25519,
    alg=CoseAlgorithms.EDDSA,
    d=unhexlify("2ffce7a0b2b825d397d0cb54f746e3da3f27596ee06b5371481dc0e012bc34d7")
)

# certificate (should contain the pubkey but is just a random string)
cert = "5865fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a" \
       "0852978bd43d28207d44486502ff7bdda632c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b7"

cert = unhexlify(cert)

cred_id = cbor2.loads(unhexlify(b"a11822822e485b786988439ebcf2"))

with open("cred_store.pickle", 'rb') as h:
    credentials_storage = pickle.load(h)


def get_peer_cred(cred_id: CoseHeaderMap):
    identifier = int.from_bytes(cred_id[CoseHeaderKeys.X5_T][1], byteorder="big")
    try:
        return unhexlify(credentials_storage[identifier])
    except KeyError:
        return None


supported = [CipherSuite.SUITE_0]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_addr = ('localhost', 9830)
sock.connect(server_addr)

ephemeral_key = OKP(
    crv=CoseEllipticCurves.X25519,
    x=unhexlify("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c"),
    d=unhexlify("8f781a095372f85b6d9f6109ae422611734d7dbfa0069a2df2935bb2e053bf35"))

init = Initiator(
    corr=Correlation.CORR_1,
    method=Method.SIGN_SIGN,
    conn_idi=unhexlify(b''),
    cred_idi=cred_id,
    auth_key=private_key,
    cred=cert,
    peer_cred=get_peer_cred,
    supported_ciphers=supported,
    selected_cipher=CipherSuite.SUITE_0,
    ephemeral_key=ephemeral_key)

msg_1 = init.create_message_one()

sock.sendall(msg_1)

msg_2 = sock.recv(500)

msg_3 = init.create_message_three(msg_2)

sock.sendall(msg_3)

conn_idi, conn_idr, aead, hashf = init.finalize()

logging.info('EDHOC key exchange successfully completed:')
logging.info(f" - connection IDr: {conn_idr}")
logging.info(f" - connection IDi: {conn_idi}")
logging.info(f" - aead algorithm: {CoseAlgorithms(aead)}")
logging.info(f" - hash algorithm: {CoseAlgorithms(hashf)}")

logging.info(f" - OSCORE secret : {init.exporter('OSCORE Master Secret', 16)}")
logging.info(f" - OSCORE salt   : {init.exporter('OSCORE Master Salt', 8)}")
