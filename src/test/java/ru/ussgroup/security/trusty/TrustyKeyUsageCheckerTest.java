package ru.ussgroup.security.trusty;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

public class TrustyKeyUsageCheckerTest {
    @Test
    public void shoulCheckKeyUsage() throws Exception {
        X509Certificate oldGostCert = TrustyUtils.loadKeyFromResources("/example/ul_gost_1.0.p12", "123456");
        X509Certificate newGostCert = TrustyUtils.loadKeyFromResources("/example/ul_gost_2.0.p12", "123456");
        X509Certificate oldRsaCert = TrustyUtils.loadKeyFromResources("/example/ul_rsa_1.0.p12", "123456");
        X509Certificate newRsaCert = TrustyUtils.loadKeyFromResources("/example/ul_rsa_2.0.p12", "123456");
        
        Assert.assertEquals(Arrays.asList(TrustyKeyUsage.SIGNING), TrustyKeyUsageChecker.getKeyUsage(oldGostCert));
        Assert.assertEquals(Arrays.asList(TrustyKeyUsage.SIGNING), TrustyKeyUsageChecker.getKeyUsage(newGostCert));
        
        Assert.assertNotEquals(Arrays.asList(TrustyKeyUsage.AUTHENTICATION), TrustyKeyUsageChecker.getKeyUsage(oldGostCert));
        Assert.assertNotEquals(Arrays.asList(TrustyKeyUsage.AUTHENTICATION), TrustyKeyUsageChecker.getKeyUsage(newGostCert));
        
        Assert.assertNotEquals(Arrays.asList(TrustyKeyUsage.SIGNING), TrustyKeyUsageChecker.getKeyUsage(oldRsaCert));
        Assert.assertNotEquals(Arrays.asList(TrustyKeyUsage.SIGNING), TrustyKeyUsageChecker.getKeyUsage(newRsaCert));
        
        Assert.assertEquals(Arrays.asList(TrustyKeyUsage.AUTHENTICATION), TrustyKeyUsageChecker.getKeyUsage(oldRsaCert));
        Assert.assertEquals(Arrays.asList(TrustyKeyUsage.AUTHENTICATION), TrustyKeyUsageChecker.getKeyUsage(newRsaCert));
    }
}
