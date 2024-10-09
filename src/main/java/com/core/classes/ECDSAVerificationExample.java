package com.core.classes;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.Security;

public class ECDSAVerificationExample {
    public static boolean verifyUsingSecp256k1(byte[] pub, byte[] dataForSigning,
    BigInteger[] rs) throws Exception {
        ECDSASigner signer = new ECDSASigner();
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(),
            params.getG(), params.getN(), params.getH());
        ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(ecParams
            .getCurve().decodePoint(pub), ecParams);
        signer.init(false, pubKeyParams);
        return signer.verifySignature(dataForSigning, rs[0].abs(), rs[1].abs());
    }

}
