# SPDX-License-Identifier: Apache-2.0
"""Writes the signed ETSI TS 119 612 fixtures of the xmldsig tests.

The script signs with lxml exclusive C14N and the cryptography package,
so the Go verifier meets a signature it did not make. It writes:

  tsl-rsa.xml     RSA-SHA256, reference URI "", a signing certificate
                  that the anchor issued, in ds:KeyInfo.
  tsl-ecdsa.xml   ECDSA-SHA256, reference URI "#tsl", the anchor itself
                  signs.
  anchor.pem      the anchor certificate of both files.
  other.pem       a certificate that did not sign or issue either file.

Run: python3 gen.py (needs lxml and cryptography). The keys stay in
memory; the script writes no private key.
"""
import base64
import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import NameOID
from lxml import etree

DS = "http://www.w3.org/2000/09/xmldsig#"
TSL = "http://uri.etsi.org/02231/v2#"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
START = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
END = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)


def name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "KE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Communications Authority of Kenya"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def cert(subject, key, issuer, issuer_key, ca):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(START).not_valid_after(END)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    algo = hashes.SHA256()
    return b.sign(issuer_key, algo)


LIST = """<tsl:TrustServiceStatusList xmlns:tsl="{tsl}" Id="tsl" TSLTag="http://uri.etsi.org/19612/TSLTag">
  <tsl:SchemeInformation>
    <tsl:TSLVersionIdentifier>5</tsl:TSLVersionIdentifier>
    <tsl:TSLSequenceNumber>{seq}</tsl:TSLSequenceNumber>
    <tsl:TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</tsl:TSLType>
    <tsl:SchemeOperatorName><tsl:Name xml:lang="en">Communications Authority of Kenya</tsl:Name></tsl:SchemeOperatorName>
    <tsl:SchemeTerritory>KE</tsl:SchemeTerritory>
    <tsl:ListIssueDateTime>2026-09-01T00:00:00Z</tsl:ListIssueDateTime>
    <tsl:NextUpdate><tsl:dateTime>2027-03-01T00:00:00Z</tsl:dateTime></tsl:NextUpdate>
  </tsl:SchemeInformation>
  <tsl:TrustServiceProviderList>
    <tsl:TrustServiceProvider>
      <tsl:TSPInformation><tsl:TSPName><tsl:Name xml:lang="en">National Registration Bureau</tsl:Name></tsl:TSPName></tsl:TSPInformation>
      <tsl:TSPServices>
        <tsl:TSPService><tsl:ServiceInformation>
          <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
          <tsl:ServiceName><tsl:Name xml:lang="en">Birth &amp; identity credentials</tsl:Name></tsl:ServiceName>
          <tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509SubjectName>CN=Registrar, O=National Registration Bureau, C=KE</tsl:X509SubjectName></tsl:DigitalId></tsl:ServiceDigitalIdentity>
          <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>
        </tsl:ServiceInformation></tsl:TSPService>
        <tsl:TSPService><tsl:ServiceInformation>
          <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
          <tsl:ServiceName><tsl:Name xml:lang="en">Old seal service</tsl:Name></tsl:ServiceName>
          <tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509SubjectName>CN=Old Seal, O=National Registration Bureau, C=KE</tsl:X509SubjectName></tsl:DigitalId></tsl:ServiceDigitalIdentity>
          <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</tsl:ServiceStatus>
        </tsl:ServiceInformation></tsl:TSPService>
      </tsl:TSPServices>
    </tsl:TrustServiceProvider>
  </tsl:TrustServiceProviderList>
</tsl:TrustServiceStatusList>"""


def c14n(el):
    return etree.tostring(el, method="c14n", exclusive=True, with_comments=False)


def sign(doc, key, chain_cert, sig_alg, ref_uri):
    root = doc.getroot()
    ds = "{%s}" % DS
    sig = etree.SubElement(root, ds + "Signature", nsmap={"ds": DS})
    sig.set("Id", "signature")
    prev = sig.getprevious()
    prev.tail = "\n  "
    sig.tail = "\n"
    si = etree.SubElement(sig, ds + "SignedInfo")
    etree.SubElement(si, ds + "CanonicalizationMethod").set("Algorithm", EXC)
    etree.SubElement(si, ds + "SignatureMethod").set("Algorithm", sig_alg)
    ref = etree.SubElement(si, ds + "Reference")
    ref.set("URI", ref_uri)
    tr = etree.SubElement(ref, ds + "Transforms")
    etree.SubElement(tr, ds + "Transform").set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    etree.SubElement(tr, ds + "Transform").set("Algorithm", EXC)
    etree.SubElement(ref, ds + "DigestMethod").set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
    dv = etree.SubElement(ref, ds + "DigestValue")
    sv = etree.SubElement(sig, ds + "SignatureValue")
    ki = etree.SubElement(sig, ds + "KeyInfo")
    xd = etree.SubElement(ki, ds + "X509Data")
    etree.SubElement(xd, ds + "X509Certificate").text = base64.b64encode(
        chain_cert.public_bytes(serialization.Encoding.DER)).decode()

    # The enveloped transform drops the Signature element but keeps the
    # text around it.
    copy = etree.fromstring(etree.tostring(root))
    csig = copy.find(ds + "Signature")
    cprev = csig.getprevious()
    cprev.tail = (cprev.tail or "") + (csig.tail or "")
    copy.remove(csig)
    dv.text = base64.b64encode(hashlib.sha256(c14n(copy)).digest()).decode()

    data = c14n(si)
    if isinstance(key, rsa.RSAPrivateKey):
        raw = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    else:
        der = key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sv.text = base64.b64encode(raw).decode()
    return etree.tostring(doc, xml_declaration=True, encoding="UTF-8")


def main():
    anchor_key = ec.generate_private_key(ec.SECP256R1())
    anchor = cert(name("Trusted List Anchor"), anchor_key, name("Trusted List Anchor"), anchor_key, True)
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = cert(name("Trusted List Signer"), signer_key, anchor.subject, anchor_key, False)
    other_key = ec.generate_private_key(ec.SECP256R1())
    other = cert(name("Other Anchor"), other_key, name("Other Anchor"), other_key, True)

    doc = etree.ElementTree(etree.fromstring(LIST.format(tsl=TSL, seq=42)))
    open("tsl-rsa.xml", "wb").write(sign(doc, signer_key, signer,
                                         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", ""))
    doc = etree.ElementTree(etree.fromstring(LIST.format(tsl=TSL, seq=43)))
    open("tsl-ecdsa.xml", "wb").write(sign(doc, anchor_key, anchor,
                                           "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "#tsl"))
    open("anchor.pem", "wb").write(anchor.public_bytes(serialization.Encoding.PEM))
    open("other.pem", "wb").write(other.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    main()
