/*
 * DUMMY TSP TEST
 */
package kz.gov.pki.kalkan.test;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.util.encoders.Base64;
import kz.gov.pki.kalkan.util.encoders.Hex;
import kz.gov.pki.kalkan.tsp.*;

/**
 * @author Aslan
 */
public class TSPTest {

	static String TSP_URL = "http://178.89.4.221/tsp/";

    public static void main(String[] args) {
        Security.addProvider(new KalkanProvider());
        byte[] data = "test".getBytes();
        TSPTest tspTest = new TSPTest();
        try {
        	// указываем алгоритм для хэширования GOST34311, GOST34311GT, SHA-1, SHA-256  
            TimeStampTokenInfo ttsInfo = tspTest.getTSTInfo(data, TSPAlgorithms.GOST34311GT);
            System.out.println("Token serial number: " + ttsInfo.getSerialNumber());
            System.out.println("Token signing time: " + ttsInfo.getGenTime());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private TimeStampTokenInfo getTSTInfo(byte[] data, String hashAlg) throws Exception {
    	MessageDigest md = MessageDigest.getInstance(hashAlg, KalkanProvider.PROVIDER_NAME);
        md.update(data);
        byte[] hash = md.digest();
        System.out.println("Hash: " + Hex.encodeStr(hash));
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        // требуем сертификат TSA
        reqGen.setCertReq(true);
        // указываем политику, чтобы сервер понял каким ключом подписать 
        // если не указывать, то по умолчанию будет применена политика
        // tsa_gostgt_policy
//        KNCAObjectIdentifiers.tsa_gost_policy - ГОСТ новый НУЦ
//        KNCAObjectIdentifiers.tsa_gostgt_policy - ГОСТ с OID текущего НУЦ 
        reqGen.setReqPolicy(KNCAObjectIdentifiers.tsa_gost_policy.getId());
        // необязательный nonce, случайное число произвольной длины
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        TimeStampRequest request = reqGen.generate(hashAlg, hash, nonce);
        byte[] reqData = request.getEncoded();
        String b64 = new String(Base64.encode(reqData));
        URL tspUrl;
        HttpURLConnection con;
        String method = "GET";
        // сервис понимает и POST и GET, можно выбрать что-то одно
        if (method.equals("GET")) {
        	tspUrl = new URL(TSP_URL + b64);
        	con = (HttpURLConnection) tspUrl.openConnection();
        } else {
        	tspUrl = new URL(TSP_URL);
        	con = (HttpURLConnection) tspUrl.openConnection();
        	con.setRequestMethod("POST");
        	con.setDoOutput(true);
        	con.setRequestProperty("Content-Type", "application/timestamp-query");
        	OutputStream reqStream = con.getOutputStream();
            reqStream.write(reqData);
            reqStream.close();
        }
        InputStream respStream = con.getInputStream();
        TimeStampResponse response = new TimeStampResponse(respStream);
        System.err.println(response.getStatus());
        System.err.println(response.getFailInfo());
        System.err.println(response.getStatusString());
        response.validate(request);
        X509CertSelector signerConstraints = response.getTimeStampToken().getSID();
        System.out.println("constraints: " + signerConstraints);
        CMSSignedData cmsData = response.getTimeStampToken().toCMSSignedData();
        CertStore certs = cmsData.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
        Collection<?> certCollection = certs.getCertificates(signerConstraints);
        Iterator<?> certIt = certCollection.iterator();
        X509Certificate cert;
        if (certIt.hasNext()) {
            System.out.print("Validating...");
            cert = (X509Certificate) certIt.next();
			// TODO проверка сертификата TSP по цепочке
            response.getTimeStampToken().validate(cert, KalkanProvider.PROVIDER_NAME);
            System.out.println(" ok!");
        } else {
            throw new TSPException("Validating certificate not found");
        }
        return response.getTimeStampToken().getTimeStampInfo();
    }
}