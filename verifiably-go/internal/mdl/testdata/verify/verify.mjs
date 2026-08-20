// Independent verification of the mdocs produced by internal/mdl.
//
// The point of this harness is that it is NOT our Go code: if both sides
// shared an implementation, a misreading of the standard would pass both.
// @owf/mdoc is the OpenWallet Foundation implementation, also used by Credo.
//
// @owf/mdoc is deliberately crypto-agnostic: it does no X.509 or COSE work
// itself, it calls out to an `MdocContext` the host supplies. The context
// below is built on Node's own `node:crypto` — a third independent
// implementation of the primitives — so nothing in the trust path traces
// back to our Go code.

import { readFileSync } from 'node:fs';
import { X509Certificate, createHash, randomBytes, webcrypto } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { IssuerSigned, MdlError } from '@owf/mdoc';
import { CoseKey, SignatureAlgorithm } from '@owf/cose';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = join(here, '..', 'vectors');

const DOCTYPE = 'org.iso.18013.5.1.mDL';
const NAMESPACE = 'org.iso.18013.5.1';
// 13 as of C.7.5: the 11 Table 3 mandatory elements (including portrait,
// added this phase) plus the two optional age attestations. Was 12 with
// portrait deliberately absent through C.7.1/C.7.2 — bump this again only if
// the emitted dataset changes, not on every vector regeneration.
const EXPECTED_ELEMENTS = 13;
// The licence in sampleLicence() expires on this date; the MSO may not
// outlive it. Hard-coded rather than read from the mdoc so the check cannot
// be satisfied by whatever the mdoc happens to claim.
const EXPIRY_DATE = new Date('2032-01-10T00:00:00Z');

// Verification clock. Defaults to wall-clock; MDL_VERIFY_NOW pins it so the
// vectors can be checked at a simulated future date. That matters because the
// certificates in the vectors legitimately expire (Annex B caps a DSC at 457
// days), and we want to know that they are good for the road ahead rather
// than merely good today.
//
// Note this is a *stricter* setting, never a looser one: `now` feeds the
// certificate-validity and MSO-validity checks, so pinning it to a future
// date can only cause failures, not mask them.
const nowOverride = process.env.MDL_VERIFY_NOW;
const NOW = nowOverride ? new Date(nowOverride) : new Date();
if (Number.isNaN(NOW.getTime())) {
  console.error(`MDL_VERIFY_NOW is not a valid date: ${nowOverride}`);
  process.exit(2);
}
if (nowOverride) console.log(`(verifying at simulated time ${NOW.toISOString()})\n`);

const mdocBytes = new Uint8Array(readFileSync(join(vectors, 'mdl_full.cbor')));
const iacaPem = readFileSync(join(vectors, 'iaca.pem'), 'utf8');
const dscPem = readFileSync(join(vectors, 'dsc.pem'), 'utf8');

const iacaCert = new X509Certificate(iacaPem);
const dscCert = new X509Certificate(dscPem);

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures += 1;
};

// --- MdocContext: Node-backed implementations of the primitives ---------

const derOf = (cert) => new Uint8Array(cert.raw);

/** Node's webcrypto verifies raw (r||s) ECDSA, which is what COSE carries. */
const subtleAlgFor = (alg) => {
  switch (alg) {
    case SignatureAlgorithm.ES256:
      return { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' };
    case SignatureAlgorithm.ES384:
      return { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' };
    case SignatureAlgorithm.ES512:
      return { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' };
    default:
      throw new Error(`harness: unsupported COSE algorithm ${alg}`);
  }
};

const ctx = {
  fetch,

  crypto: {
    random: (length) => new Uint8Array(randomBytes(length)),
    digest: ({ digestAlgorithm, bytes }) =>
      new Uint8Array(createHash(digestAlgorithm.replace('-', '')).update(bytes).digest()),
    hdkf: () => {
      // Only needed for session encryption (18013-5 device retrieval), which
      // this harness does not exercise.
      throw new Error('harness: HKDF not implemented; not needed for issuance');
    },
  },

  cose: {
    sign1: {
      sign: () => {
        throw new Error('harness: signing not implemented; this harness only verifies');
      },
      verify: async ({ toBeVerified, signature, key, algorithm }) => {
        const alg = algorithm ?? key.algorithm ?? SignatureAlgorithm.ES256;
        const params = subtleAlgFor(alg);
        const imported = await webcrypto.subtle.importKey(
          'jwk',
          key.jwk,
          { name: params.name, namedCurve: params.namedCurve },
          false,
          ['verify'],
        );
        return webcrypto.subtle.verify(
          { name: params.name, hash: params.hash },
          imported,
          signature,
          toBeVerified,
        );
      },
    },
    mac0: {
      generate: () => {
        throw new Error('harness: MAC0 not implemented; not needed for issuance');
      },
      verify: () => {
        throw new Error('harness: MAC0 not implemented; not needed for issuance');
      },
    },
  },

  x509: {
    getIssuerNameField: ({ certificate, field }) => {
      const cert = new X509Certificate(Buffer.from(certificate));
      return cert.issuer
        .split('\n')
        .map((line) => line.split('='))
        .filter(([k]) => k.trim() === field)
        .map(([, v]) => v.trim());
    },

    getPublicKey: async ({ certificate, algorithm }) => {
      const cert = new X509Certificate(Buffer.from(certificate));
      const jwk = cert.publicKey.export({ format: 'jwk' });
      const key = CoseKey.fromJwk(jwk);
      // fromJwk carries no `alg` when the JWK has none; the COSE header's
      // algorithm is authoritative here.
      if (algorithm !== undefined && key.algorithm === undefined) {
        return CoseKey.create({
          keyType: key.keyType,
          curve: key.curve,
          x: key.x,
          y: key.y,
          algorithm,
        });
      }
      return key;
    },

    /**
     * Real path validation: every certificate must be signed by the next one
     * up, and the top must be one of the trust anchors. Node's
     * X509Certificate.verify(publicKey) checks the signature; checkValidity
     * is applied against `now`.
     */
    verifyCertificateChain: ({ trustedCertificates, x5chain, now = NOW }) => {
      if (!x5chain || x5chain.length === 0) {
        throw new Error('harness: empty x5chain');
      }
      const chain = x5chain.map((der) => new X509Certificate(Buffer.from(der)));
      const anchors = trustedCertificates.map((der) => new X509Certificate(Buffer.from(der)));

      for (const cert of chain) {
        if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
          throw new Error(`harness: certificate ${cert.subject} is not valid at ${now.toISOString()}`);
        }
      }

      // Link the presented chain together, leaf first.
      for (let i = 0; i < chain.length - 1; i += 1) {
        if (!chain[i].verify(chain[i + 1].publicKey)) {
          throw new Error(`harness: ${chain[i].subject} is not signed by ${chain[i + 1].subject}`);
        }
      }

      // Anchor the top of the presented chain in a trusted certificate.
      //
      // A self-anchored chain (the top certificate IS the trust anchor) is
      // only legitimate when that certificate is a CA. Without the `ca`
      // check, a single-certificate x5chain carrying just the DSC, anchored
      // to the DSC itself, would be accepted — a leaf trusting itself.
      const top = chain[chain.length - 1];
      const anchor = anchors.find((a) => {
        if (a.raw.equals(top.raw)) return a.ca;
        return top.verify(a.publicKey) && a.ca;
      });
      if (!anchor) {
        throw new Error('harness: chain does not terminate in a trusted CA certificate');
      }
      if (now < new Date(anchor.validFrom) || now > new Date(anchor.validTo)) {
        throw new Error('harness: trust anchor is not valid at verification time');
      }

      const out = chain.map((c) => new Uint8Array(c.raw));
      if (!anchor.raw.equals(top.raw)) out.push(new Uint8Array(anchor.raw));
      return { chain: out };
    },

    getCertificateData: ({ certificate }) => {
      const cert = new X509Certificate(Buffer.from(certificate));
      return {
        issuerName: cert.issuer,
        subjectName: cert.subject,
        serialNumber: cert.serialNumber,
        thumbprint: cert.fingerprint256,
        notBefore: new Date(cert.validFrom),
        notAfter: new Date(cert.validTo),
        pem: cert.toString(),
      };
    },
  },
};

// --- Checks -------------------------------------------------------------

// 1. The mdoc parses under @owf/mdoc's own CBOR schemas. This is not a
//    permissive read: IssuerSigned.decode runs the zod codec over the whole
//    structure, so a mis-tagged item or a wrong map key fails here.
let issuerSigned;
try {
  issuerSigned = IssuerSigned.decode(mdocBytes);
  check('IssuerSigned decodes under @owf/mdoc schemas', true);
} catch (err) {
  check('IssuerSigned decodes under @owf/mdoc schemas', false, err.message);
  console.log('\nCannot continue without a parsed IssuerSigned.');
  process.exit(1);
}

const mso = issuerSigned.issuerAuth.mobileSecurityObject;

// 2. Full cryptographic verification: COSE_Sign1 signature over the MSO,
//    DSC -> IACA chain built to the trust anchor, MSO validity window against
//    both the DSC's own validity and the current clock, and — the important
//    one — every disclosed item re-hashed and matched against the committed
//    digest in valueDigests.
//
//    Every FAILED assessment is collected rather than thrown, so one failure
//    does not mask the rest.
const assessments = [];
try {
  const result = await issuerSigned.verify(
    {
      now: NOW,
      trustedCertificates: [{ issuance: [derOf(iacaCert)] }],
      // No status list in the MSO; skip the network fetch it would imply.
      disableStatusValidation: true,
      verificationCallback: (a) => assessments.push(a),
    },
    ctx,
  );
  const failed = assessments.filter((a) => a.status === 'FAILED');
  for (const a of failed) {
    console.log(`      failed assessment [${a.category}] ${a.check}${a.reason ? `: ${a.reason}` : ''}`);
  }
  check(
    'full issuer verification (signature, chain, digests)',
    failed.length === 0,
    `${assessments.length} assessments, ${failed.length} failed`,
  );
  check(
    'chain terminates in the IACA trust anchor',
    !!result.trustedIssuanceChain && result.trustedIssuanceChain.length >= 2,
    result.trustedIssuanceChain
      ? `${result.trustedIssuanceChain.length} certificates`
      : 'no trusted chain',
  );
} catch (err) {
  check('full issuer verification (signature, chain, digests)', false,
    err instanceof MdlError ? err.message : String(err));
  check('chain terminates in the IACA trust anchor', false, 'verification threw');
}

// Prove the digest checks above were real work and not a vacuous pass over an
// empty item list.
const digestChecks = assessments.filter(
  (a) => a.category === 'DATA_INTEGRITY' && a.check.includes('calculated digest'),
);
check(
  'every disclosed element had its digest recomputed',
  digestChecks.length === EXPECTED_ELEMENTS,
  `${digestChecks.length} digest comparisons`,
);

// 3. Negative control: the same mdoc must FAIL against a trust anchor that
//    did not issue it. Without this, a context bug that made
//    verifyCertificateChain always succeed would go unnoticed.
try {
  const bogus = [];
  await issuerSigned.verify(
    {
      now: NOW,
      // The DSC is a leaf, not a CA — anchoring to it must not validate.
      trustedCertificates: [{ issuance: [derOf(dscCert)] }],
      disableStatusValidation: true,
      verificationCallback: (a) => bogus.push(a),
    },
    ctx,
  );
  const chainFailed = bogus.some(
    (a) => a.status === 'FAILED' && a.check.toLowerCase().includes('certificate'),
  );
  check('verification fails against an unrelated trust anchor', chainFailed);
} catch {
  // defaultVerificationCallback would throw; ours collects, so a throw here
  // still means the wrong anchor was rejected.
  check('verification fails against an unrelated trust anchor', true, 'rejected by throw');
}

// 4. Structural claims the brief calls for, read from @owf/mdoc's own parse of
//    the MSO — these are now checks on content whose integrity step 2 already
//    established.
check('docType is org.iso.18013.5.1.mDL', mso.docType === DOCTYPE, mso.docType);

const digestIds = mso.valueDigests.getDigestIdsForNamespace(NAMESPACE);
check(
  'valueDigests present for the ISO namespace',
  mso.valueDigests.getNamespaces().includes(NAMESPACE),
  mso.valueDigests.getNamespaces().join(', '),
);
check(
  `${EXPECTED_ELEMENTS} elements committed`,
  digestIds.length === EXPECTED_ELEMENTS,
  String(digestIds.length),
);

const items = issuerSigned.getIssuerNamespace(NAMESPACE) ?? [];
check(
  `${EXPECTED_ELEMENTS} disclosable items in the ISO namespace`,
  items.length === EXPECTED_ELEMENTS,
  String(items.length),
);

const validity = mso.validityInfo;
check('validityInfo present', !!validity);
check(
  'validUntil does not exceed expiry_date',
  !!validity && validity.validUntil <= EXPIRY_DATE,
  validity ? validity.validUntil.toISOString() : '',
);
check(
  'validFrom precedes validUntil',
  !!validity && validity.validFrom < validity.validUntil,
);

// 5. The device key is what makes the credential non-clonable; an MSO without
//    it is a bearer token.
check(
  'MSO binds a device key',
  !!mso.deviceKeyInfo?.deviceKey,
  mso.deviceKeyInfo?.deviceKey ? `curve ${mso.deviceKeyInfo.deviceKey.curve}` : 'absent',
);

// 6. The vectors are fixtures in two other repos. Annex B caps a DSC at 457
//    days, so they do expire; warn while there is still time to regenerate
//    rather than letting a downstream repo hit an inscrutable chain error.
//    Skipped when the clock is simulated, where "remaining life" is moot.
if (!nowOverride) {
  const daysLeft = Math.floor((new Date(dscCert.validTo) - NOW) / 86400000);
  check(
    'DSC has at least 60 days of validity left',
    daysLeft >= 60,
    `${daysLeft} days (regenerate the vectors when this fails)`,
  );
}

// 7. Proof-of-concept material must be labelled as such.
check('IACA is marked POC', iacaCert.subject.includes('POC-DO-NOT-TRUST'), iacaCert.subject.replace(/\n/g, ', '));
check('DSC is marked POC', dscCert.subject.includes('POC-DO-NOT-TRUST'), dscCert.subject.replace(/\n/g, ', '));

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
