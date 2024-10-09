package com.core.classes;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.math.ec.ECPoint;
import java.security.interfaces.ECPrivateKey;
import com.google.gson.JsonObject;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;


public class ContainerECDSA {

    public ContainerECDSA() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public JsonObject generateKeys() {
        try {
            // Use the secp256k1 curve, which is commonly used for Bitcoin
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyPairGenerator.initialize(ecSpec);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            ECPrivateKey privateKeyEC = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey publicKeyEC = (ECPublicKey) keyPair.getPublic();

            String privateKey = privateKeyEC.getS().toString(16);
            String publicKey = "04" + publicKeyEC.getW().getAffineX().toString(16) +
                    publicKeyEC.getW().getAffineY().toString(16);

            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("public_key", publicKey);
            jsonObject.addProperty("secret_key", privateKey);

            return jsonObject;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String generateWalletAddres(String publicKey) {
        try {
            // Преобразование публичного ключа в байты
            byte[] publicKeyByte = Hex.decode(publicKey);

            // Хеширование публичного ключа с использованием Keccak-256
            MessageDigest keccakDigest = new Keccak.Digest256();
            byte[] keccakHash = keccakDigest.digest(publicKeyByte);

            // Взятие последних 20 байтов
            byte[] walletAddresBytes = new byte[20];
            System.arraycopy(keccakHash, keccakHash.length - 20, walletAddresBytes, 0, 20);

            // Преобразование в шестнадцатеричную строку
            return "0x" + Hex.toHexString(walletAddresBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean verifyECDSASignature(String publicKeyString, String data, String signature) {
        System.out.println(publicKeyString + " " + publicKeyString.length());
        System.out.println(data);
        System.out.println(signature + " " + signature.length());

        try {
            byte[] publicKeyBytes = Hex.decode(publicKeyString);

            ECNamedCurveParameterSpec curveParams = ECNamedCurveTable.getParameterSpec("secp256k1");
            ECCurve curve = curveParams.getCurve();
            ECPoint ecPoint = curve.decodePoint(publicKeyBytes);

            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, curveParams);

            try {
                KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
                ecdsaVerify.initVerify(publicKey);

                ecdsaVerify.update(data.getBytes());
                byte[] signatureBytesCompact = hexStringToByteArray(signature);
                byte[] signatureBytes;

                if (signatureBytesCompact.length == 64) {
                    signatureBytes = compactToDER(signatureBytesCompact);
                } else {
                    signatureBytes = Hex.decode(signature);
                }
                System.out.println("Compact: " + signatureBytesCompact.length + " DER: " + signatureBytes.length);

                // if (signatureBytes == null) {
                //     System.err.println("Error: uncorrected format signature.");
                //     return false;
                // } 
                System.out.println("1");
                return ecdsaVerify.verify(signatureBytes);

            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] compactToDER(byte[] compactSignature) throws SignatureException {
        if (compactSignature.length != 64) {
            throw new SignatureException("Invalid compact signature length");
        }

        byte[] r = new byte[32];
        byte[] s = new byte[32];

        System.arraycopy(compactSignature, 0, r, 0, 32);
        System.arraycopy(compactSignature, 32, s, 0, 32);

        byte[] derSignature = new byte[72];
        derSignature[0] = 0x30; // SEQUENCE
        derSignature[1] = 0x46; // Length of remaining bytes

        derSignature[2] = 0x02; // INTEGER (r)
        derSignature[3] = 0x21; // Length of r
        System.arraycopy(r, 0, derSignature, 4, 32);

        derSignature[36] = 0x02; // INTEGER (s)
        derSignature[37] = 0x21; // Length of s
        System.arraycopy(s, 0, derSignature, 38, 32);

        return derSignature;
    }

    public ECPublicKeyParameters createPublicKeyFromHex(String hexPublicKey) {
        // Кривая secp256r1 (эллиптическая кривая по стандарту NIST)
        X9ECParameters ecParams = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters domainParameters = new ECDomainParameters(ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());

        // Преобразование hex-строки в байты
        byte[] publicKeyBytes = Hex.decode(hexPublicKey);

        // Создание объекта ECPoint из байтов
        ECPoint ecPoint = ecParams.getCurve().decodePoint(publicKeyBytes);

        // Создание публичного ключа
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(ecPoint, domainParameters);

        return publicKeyParameters;
    }

    public byte[] signMessage(ECPrivateKey privateKey, String message) {
        try {
            Signature ecdsaSing = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSing.initSign(privateKey);
            ecdsaSing.update(message.getBytes());

            return ecdsaSing.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }



    public ECPrivateKey privateKeyFromHex(String privateKeyHex) {
        try {
            privateKeyHex = privateKeyHex.replace("0x", "");

            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

            return (ECPrivateKey) keyFactory.generatePrivate(new ECPrivateKeySpec(new BigInteger(privateKeyHex, 16), ecSpec));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String addLeadingByte(String key) {
        if (key.length() % 2 != 0) {
            key = "0" + key; // Ensure an even number of characters
        }
        return "0x" + key;
    }

    private static byte[] hexStringToByteArray(String hex) {
        try {
            int len = hex.length();
            if (len % 2 != 0) {
                // Если длина строки нечетная, добавим в начало нуль
                hex = "0" + hex;
                len++;
            }

            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                        | Character.digit(hex.charAt(i + 1), 16));
            }

            return data;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
