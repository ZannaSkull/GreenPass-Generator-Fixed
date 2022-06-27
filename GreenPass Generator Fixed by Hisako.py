
"""
Covid1984 Green Pass Generator Fixed by Hisako🪐#1359
"""

from zlib import compress
from binascii import unhexlify

from base45 import b45encode
from flynn import encoder as flynn_encoder
from flynn import decoder as flynn_decoder
import qrcode
from cose.messages import Sign1Message
from cose.headers import Algorithm, KID
from cose.algorithms import EdDSA
from cose.keys.curves import Ed25519
from cose.keys import OKPKey

DATA = {

  1: "DE",
  4: 1655209933,
  6: 1623673933,
  -260: { 
    1: {
      "v": [
        {
          "ci": "URN:UVCI:01DE/IZ12345A/21E0JXD7UQY6ECLM3WT7YF#8",
          "co": "DE",
          "dn": 2,
          "dt": "2021-04-01",
          "is": "Fabrica di cioccolato",
          "ma": "ORG-100031184",
          "mp": "EU/1/20/1507",
          "sd": 2,
          "tg": "840539006",
          "vp": "1119349007"
        }
      ],
      "dob": "2007-02-24",
      "nam": {
        "fn": "UwU",
        "gn": "QwQ",
        "fnt": "UWU",
        "gnt": "QWQ"
      },
      "ver": "1.0.0"
    }
  }
}

# just 32 random bytes generated with `openssl rand -hex 32`
PRIVKEY = b"9d370d925476752486ab0e4a8e088228e493da12d1586fafae9f35880dbcfe03"

# using an already signed header from a real certificate adds info on the issuer in the checker apps
HEADER = b""

def main():
    msg = Sign1Message(phdr={Algorithm: EdDSA, KID: b"kid2"},
                       payload=flynn_encoder.dumps(DATA))

    privkey = unhexlify(PRIVKEY)
    cose_key = OKPKey(crv=Ed25519, d=privkey, optional_params={"ALG": "EDDSA"})

    msg.key = cose_key

    signed_encoded = msg.encode()

    (_, (header_1, header_2, cbor_payload, sign)) = flynn_decoder.loads(signed_encoded)

    if HEADER:
        header_1 = HEADER

    signed_encoded = flynn_encoder.dumps((header_1, header_2, cbor_payload, sign))

    qr_encoded = qrcode.make(b"HC1:" + b45encode(compress(signed_encoded)))

    qr_encoded.save("./qr.png")


if __name__ == "__main__":
    main()
