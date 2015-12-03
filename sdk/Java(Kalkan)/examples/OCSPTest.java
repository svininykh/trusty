/*
 * DUMMY OCSP TEST
 */
package kz.gov.pki.kalkan.test;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.cryptopro.CryptoProObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.ocsp.*;
import kz.gov.pki.kalkan.util.encoders.Base64;

/**
 * @author Aslan
 */
public class OCSPTest {

	static final String CA_CERT_FILE = "c:/raw/ca_certs/nca/gost_root.cer";
	static final String CERT_FILE = "c:/raw/gost_real_rev.cer";
	static final String OCSP_URL = "http://178.89.4.221/ocsp/";
	static X509Certificate cacert, cert;
	static byte[] nonce;

	public static void main(String[] args) {
		Security.addProvider(new KalkanProvider());
		try {
			URL url;
			HttpURLConnection con;
			OutputStream os;
			cert = generateCert(CERT_FILE);
			System.out.println(cert.getSerialNumber());
			cacert = generateCert(CA_CERT_FILE);
			// указываем алгоритм хэширования
			//CertificateID.HASH_GOST34311GT
			//CertificateID.HASH_GOST34311
			//CertificateID.HASH_SHA256
			//CertificateID.HASH_SHA1
			byte[] ocspReq = getOcspPackage(cert.getSerialNumber(), cacert,
					CertificateID.HASH_GOST34311GT);
			String b64Req = new String(Base64.encode(ocspReq));
			// сервис понимает и POST и GET, можно выбрать что-то одно
			if (b64Req.length() <= 255) {
				url = new URL(OCSP_URL + b64Req);
				con = (HttpURLConnection) url.openConnection();
			} else {
				url = new URL(OCSP_URL);
				con = (HttpURLConnection) url.openConnection();
				con.setDoOutput(true);
				con.setRequestMethod("POST");
				con.setRequestProperty("Content-Type",
						"application/ocsp-request");
				os = con.getOutputStream();
				os.write(ocspReq);
				os.close();
			}
			
			makeOcspResponse(con);
			con.disconnect();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void makeOcspResponse(HttpURLConnection con)
			throws Exception {
		InputStream in = con.getInputStream();
		OCSPResp response = new OCSPResp(in);
		in.close();

		if (response.getStatus() != 0) {
			throw new OCSPException("Unsuccessful request. Status: "
					+ response.getStatus());
		}
		BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
		byte[] respNonceExt = brep
				.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce
						.getId());
		if (respNonceExt != null) {
			ASN1InputStream asn1In = new ASN1InputStream(respNonceExt);
			DERObject derObj = asn1In.readObject();
			asn1In.close();
			byte[] extV = DEROctetString.getInstance(derObj).getOctets();
			asn1In = new ASN1InputStream(extV);
			derObj = asn1In.readObject();
			asn1In.close();
			System.out.println("nonces are equal: "
					+ java.util.Arrays.equals(nonce, DEROctetString.getInstance(derObj).getOctets()));
		}
		X509Certificate ocspcert = brep.getCerts(KalkanProvider.PROVIDER_NAME)[0];

		// TODO проверка сертификата OCSP по цепочке

		System.out.println("OCSP Response sigAlg: "
				+ brep.getSignatureAlgName());
		System.out.println("OCSP Response verify: "
				+ brep.verify(ocspcert.getPublicKey(), KalkanProvider.PROVIDER_NAME));

		SingleResp[] singleResps = brep.getResponses();
		SingleResp singleResp = singleResps[0];
		Object status = singleResp.getCertStatus();

		if (status == null) {
			System.out.println("OCSP Response is GOOD");
		}
		if (status instanceof RevokedStatus) {
			System.out.println("OCSP Response is REVOKED");
			if (((RevokedStatus) status).hasRevocationReason()) {
				System.out.println("Time: "
						+ ((RevokedStatus) status).getRevocationTime());
				System.out.println("Reason: "
						+ ((RevokedStatus) status).getRevocationReason());
			}
		}
		if (status instanceof UnknownStatus) {
			System.out.println("OCSP Response is UNKNOWN");
		}
	}

	private static byte[] getOcspPackage(BigInteger serialNr,
			Certificate cacert, String hashAlg) throws Exception {
		OCSPReqGenerator gen = new OCSPReqGenerator();
		CertificateID certId = new CertificateID(hashAlg,
				(X509Certificate) cacert, serialNr,
				KalkanProvider.PROVIDER_NAME);
		gen.addRequest(certId);
		gen.setRequestExtensions(generateExtensions());
		OCSPReq req;
		req = gen.generate();
		return req.getEncoded();
	}

	private static X509Extensions generateExtensions() {
		SecureRandom sr = new SecureRandom();
		nonce = new byte[4];
		sr.nextBytes(nonce);
		Hashtable exts = new Hashtable();
		X509Extension nonceext = new X509Extension(false,
				new DEROctetString(new DEROctetString(nonce)));
		// добавляем необязательный nonce, случайное число произвольной длины 
		exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, nonceext);

		// добавляем расширение предпочтительного1 алгоритм,
		// чтобы сервер знал каким ключом подписать ответ
		// если не указать, будет использован ключ текущего НУЦ со старым oid 
		ASN1EncodableVector prefSigAlgV = new ASN1EncodableVector();
//		prefSigAlgV.add(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411_94_with_gostR34310_2004));
		prefSigAlgV.add(new AlgorithmIdentifier(KNCAObjectIdentifiers.gost34311_95_with_gost34310_2004));
		DERSequence prefSigAlgSeq = new DERSequence(prefSigAlgV);
		ASN1EncodableVector prefSigAlgsV = new ASN1EncodableVector();
		prefSigAlgsV.add(prefSigAlgSeq);
		DERSequence prefSigAlgsSeq = new DERSequence(prefSigAlgsV);
		X509Extension psaext = new X509Extension(false,
				new DEROctetString(prefSigAlgsSeq));
		exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_pref_sig_algs, psaext);
		
		return new X509Extensions(exts);
	}

	private static X509Certificate generateCert(String certFile)
			throws Exception {
		return (X509Certificate) CertificateFactory.getInstance("X.509",
				KalkanProvider.PROVIDER_NAME).generateCertificate(
				new FileInputStream(certFile));
	}
}