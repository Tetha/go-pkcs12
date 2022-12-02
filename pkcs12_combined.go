package pkcs12 // import "software.sslmate.com/src/go-pkcs12"

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
)

func EncodeCombinedKeyAndTrustStore(rand io.Reader,
	privateKey interface{},
	certificate *x509.Certificate,
	caCerts []*x509.Certificate,
	trustedCerts []*x509.Certificate,
	password string) (pfxData []byte, err error) {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}

	var pfx pfxPdu
	pfx.Version = 3

	var certFingerprint = sha1.Sum(certificate.Raw)
	var localKeyIdAttr pkcs12Attribute
	localKeyIdAttr.Id = oidLocalKeyID
	localKeyIdAttr.Value.Class = 0
	localKeyIdAttr.Value.Tag = 17
	localKeyIdAttr.Value.IsCompound = true
	if localKeyIdAttr.Value.Bytes, err = asn1.Marshal(certFingerprint[:]); err != nil {
		return nil, err
	}

	var certBags []safeBag
	var certBag *safeBag
	if certBag, err = makeCertBag(certificate.Raw, []pkcs12Attribute{localKeyIdAttr}); err != nil {
		return nil, err
	}
	certBags = append(certBags, *certBag)

	for _, cert := range caCerts {
		if certBag, err = makeCertBag(cert.Raw, []pkcs12Attribute{}); err != nil {
			return nil, err
		}
		certBags = append(certBags, *certBag)
	}

	var keyBag safeBag
	keyBag.Id = oidPKCS8ShroundedKeyBag
	keyBag.Value.Class = 2
	keyBag.Value.Tag = 0
	keyBag.Value.IsCompound = true
	if keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBag(rand, privateKey, encodedPassword); err != nil {
		return nil, err
	}
	keyBag.Attributes = append(keyBag.Attributes, localKeyIdAttr)

	// and now go ahead and add the trust bytes
	extKeyUsageOidBytes, err := asn1.Marshal(oidAnyExtendedKeyUsage)
	if err != nil {
		return nil, err
	}

	var certsWithFriendlyNames []TrustStoreEntry
	for _, cert := range trustedCerts {
		certsWithFriendlyNames = append(certsWithFriendlyNames, TrustStoreEntry{
			Cert:         cert,
			FriendlyName: cert.Subject.String(),
		})
	}

	var certAttributes []pkcs12Attribute

	// the oidJavaTrustStore attribute contains the EKUs for which
	// this trust anchor will be valid
	certAttributes = append(certAttributes, pkcs12Attribute{
		Id: oidJavaTrustStore,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
			Bytes:      extKeyUsageOidBytes,
		},
	})

	for _, entry := range certsWithFriendlyNames {

		bmpFriendlyName, err := bmpString(entry.FriendlyName)
		if err != nil {
			return nil, err
		}

		encodedFriendlyName, err := asn1.Marshal(asn1.RawValue{
			Class:      0,
			Tag:        30,
			IsCompound: false,
			Bytes:      bmpFriendlyName,
		})
		if err != nil {
			return nil, err
		}

		friendlyName := pkcs12Attribute{
			Id: oidFriendlyName,
			Value: asn1.RawValue{
				Class:      0,
				Tag:        17,
				IsCompound: true,
				Bytes:      encodedFriendlyName,
			},
		}

		certBag, err := makeCertBag(entry.Cert.Raw, append(certAttributes, friendlyName))
		if err != nil {
			return nil, err
		}
		certBags = append(certBags, *certBag)
	}

	// Construct an authenticated safe with two SafeContents.
	// The first SafeContents is encrypted and contains the cert bags.
	// The second SafeContents is unencrypted and contains the shrouded key bag.
	var authenticatedSafe [3]contentInfo
	if authenticatedSafe[0], err = makeSafeContents(rand, certBags, encodedPassword); err != nil {
		return nil, err
	}
	if authenticatedSafe[1], err = makeSafeContents(rand, []safeBag{keyBag}, nil); err != nil {
		return nil, err
	}
	if authenticatedSafe[2], err = makeSafeContents(rand, certBags, encodedPassword); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	// compute the MAC
	pfx.MacData.Mac.Algorithm.Algorithm = oidSHA1
	pfx.MacData.MacSalt = make([]byte, 8)
	if _, err = rand.Read(pfx.MacData.MacSalt); err != nil {
		return nil, err
	}
	pfx.MacData.Iterations = 1
	if err = computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
		return nil, err
	}

	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, errors.New("pkcs12: error writing P12 data: " + err.Error())
	}
	return
}
