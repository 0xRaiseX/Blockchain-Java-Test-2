package com.core.classes;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
// import org.bouncycastle.crypto.Signer;
import com.google.gson.JsonObject;
import java.security.Signature;
import java.security.SignatureException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;


public class ECDSAKeyGenerator {

    public static void main(String[] args) {
        String message = "test data";

        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = generateKeyPair();

        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        String privateKeyString = privateKey.getS().toString(16);
        String publicKeyString = "04" + publicKey.getW().getAffineX().toString(16) +
                publicKey.getW().getAffineY().toString(16);

        // ECPrivateKey publicKEy2 = privateKeyFromHex(privateKeyString);
        // String privateKeyString2 = publicKEy2.getS().toString(16);

        byte[] signature = signMessage(privateKey, message);
        
        boolean is = verifySignature(publicKey, message, signature);
        System.out.println("Длина подписи: " + signature.length + " байт");

        try {
            // Извлекаем r и s из DER-подписи
            BigInteger[] rs = extractRSFromDER(signature);

            // Выводим значения r и s
            System.out.println("r: " + rs[0].toString(16) + " " + rs[0].toByteArray().length);
            System.out.println("s: " + rs[1].toString(16) + " " + rs[1].toByteArray().length);
        
        // int halfLength = signature.length / 2;
        // byte[] rBytes = new byte[halfLength];
        // byte[] sBytes = new byte[halfLength];
        // System.arraycopy(signature, 0, rBytes, 0, halfLength);
        // System.arraycopy(signature, halfLength, sBytes, 0, halfLength);

        // // Создайте объекты BigInteger из массивов байт
        // java.math.BigInteger r = new java.math.BigInteger(1, rBytes);
        // java.math.BigInteger s = new java.math.BigInteger(1, sBytes);

        // // Выведите значения r и s
        // System.out.println("r: " + r.toString(16) + " " + r.toByteArray().length);
        // System.out.println("s: " + s.toString(16) + " " + s.toByteArray().length);


        String hexString = Hex.toHexString(signature);
        System.out.println(hexString);

        System.out.println(is);

        boolean s3 = verifyECDSASignature3(publicKeyString, hexString, message.getBytes());
        System.out.println(s3);


        ECPublicKeyParameters publicKeyParameters = createPublicKeyFromHex(publicKeyString);
        ECPoint ecPoint = publicKeyParameters.getQ();
        // Получение координат x и y
        BigInteger xCoordinate = ecPoint.getXCoord().toBigInteger();
        BigInteger yCoordinate = ecPoint.getYCoord().toBigInteger();
        String xHex = xCoordinate.toString(16);
        String yHex = yCoordinate.toString(16);

        String publicKey5 = "04" + xHex + yHex;

        System.out.println(publicKey5);

        if (publicKey5.equals(publicKeyString)) {
            System.out.println("True. Публчиные ключи равны");
        }
        

        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, publicKeyParameters);

        if (verifier.verifySignature(message.getBytes(),  rs[0], rs[1])) {
            System.out.println("Подпись верна");
        } else {
            System.out.println("Подпись неверна");
        }
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        
        boolean g = ContainerKeys.verifyECDSASignature(publicKeyString, message, Hex.toHexString(signature));
        System.out.println(g);

        boolean g2 = verifyECDSASignature3(publicKeyString, Hex.toHexString(signature), message.getBytes());
        System.out.println(g2);
    }

    private static BigInteger[] extractRSFromDER(byte[] derSignature) throws SignatureException {
        try {
            // Первый байт должен быть тег SEQUENCE (0x30)
            if (derSignature[0] != 0x30) {
                throw new SignatureException("Invalid DER-encoding for ECDSA signature");
            }

            // Второй байт должен указывать на длину последовательности
            int seqLength = derSignature[1] & 0xFF;

            // Определяем, сколько байт отводится под r и s
            int rLength = derSignature[3] & 0xFF;
            int sLength = derSignature[5 + rLength] & 0xFF;

            // Извлекаем r и s как массивы байтов
            byte[] rBytes = new byte[rLength];
            byte[] sBytes = new byte[sLength];
            System.arraycopy(derSignature, 4, rBytes, 0, rLength);
            System.arraycopy(derSignature, 6 + rLength, sBytes, 0, sLength);

            // Преобразуем r и s в объекты BigInteger
            BigInteger r = new BigInteger(1, rBytes);
            BigInteger s = new BigInteger(1, sBytes);

            return new BigInteger[]{r, s};
        } catch (Exception e) {
            throw new SignatureException("Failed to extract r and s from DER-encoded signature", e);
        }
    }


    public static ECPublicKeyParameters createPublicKeyFromHex(String hexPublicKey) {
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

    

    public static boolean verifyECDSASignature3(String publicKeyHex, String signatureHex, byte[] message) {
        try {
            // byte[] publicKeyBytes = Hex.decode(publicKeyHex);
            // byte[] signatureBytes = Hex.decode(signatureHex);
            

            // // Extract x and y coordinates from the uncompressed format
            // BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 1, 33));
            // BigInteger y = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 33, 65));
            publicKeyHex = publicKeyHex.startsWith("04") ? publicKeyHex.substring(2) : publicKeyHex;
            System.out.println(publicKeyHex.length());
        // Split the hex string into x and y coordinates
            String hex_x = publicKeyHex.substring(0, 64);
            String hex_y = publicKeyHex.substring(64);
            // System.out.println(hex_x);
            // System.out.println(hex_y);
            // Convert hex strings to BigInteger
            // BigInteger x = new BigInteger(hex_x, 16);
            // BigInteger y = new BigInteger(hex_y, 16);

            java.math.BigInteger x = new java.math.BigInteger(hex_x, 16);
            java.math.BigInteger y = new java.math.BigInteger(hex_y, 16);

            // System.out.println(x);
            // System.out.println(y);
            // Create an ECPoint object from x and y coordinates
            ECPoint ecPoint = CustomNamedCurves.getByName("secp256k1").getCurve().createPoint(x, y);

            // System.out.println("Decimal format: " + ecPoint.toString());
            // Create an ECDomainParameters object
            X9ECParameters curveParams = CustomNamedCurves.getByName("secp256k1");
            ECDomainParameters domainParameters = new ECDomainParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());

            // Create an ECPublicKeyParameters object
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(ecPoint, domainParameters);

            // Verify the signature
            ECDSASigner signer = new ECDSASigner(new RandomDSAKCalculator());
            signer.init(false, publicKeyParameters);

            byte[] signatureBytes = Hex.decode(signatureHex);
            System.out.println(Hex.toHexString(signatureBytes));
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(signatureBytes, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(signatureBytes, 32, 64));

            return signer.verifySignature(message, r, s);

            // Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
            // ecdsaVerify.initVerify(publicKey);
            // ecdsaVerify.update(message.getBytes());

            // return ecdsaVerify.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    
    public static KeyPair generateKeyPair() {
        try {
            // Use the secp256k1 curve, which is commonly used for Bitcoin
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyPairGenerator.initialize(ecSpec);

            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean verifySignature(ECPublicKey publicKey, String message, byte[] signature) {
        try {
            if (publicKey == null) {
                System.out.println("Invalid public key");
                return false;
            }

            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(message.getBytes());

            return ecdsaVerify.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    public static byte[] signMessage(ECPrivateKey privateKey, String message) {
        try {
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(message.getBytes("UTF-8"));

            return ecdsaSign.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public static ECPrivateKey privateKeyFromHex(String hex) {
        try {
            hex = hex.replace("0x", "");

            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

            return (ECPrivateKey) keyFactory.generatePrivate(new ECPrivateKeySpec(new BigInteger(hex, 16), ecSpec));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static ECPublicKey publicKeyFromHex(String hex) {
        try {
            hex = hex.replace("0x", "");
    
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    
            int keySize = (((DSAExt) ecSpec).getOrder().bitLength() + 7) / 8; // Calculate key size in bytes
    
            byte[] keyBytes = new byte[keySize * 2]; // Assuming public key is uncompressed
    
            for (int i = 0; i < keyBytes.length; i++) {
                keyBytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
            }
    
            java.security.spec.ECPoint ecPoint = new java.security.spec.ECPoint(new BigInteger(1, Arrays.copyOfRange(keyBytes, 0, keySize)),
                                          new BigInteger(1, Arrays.copyOfRange(keyBytes, keySize, 2 * keySize)));
    
            return (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(ecPoint, ecSpec));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public static boolean verifySignature2(String data, String signatureHex, String publicKeyHex) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Load the SECP256k1 curve parameters
        X9ECParameters params = CustomNamedCurves.getByName("secp256k1");
        ECDomainParameters curveParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

        // Convert hex strings to byte arrays
        byte[] signatureBytes = hexStringToByteArray(signatureHex);
        byte[] publicKeyBytes = hexStringToByteArray(publicKeyHex);

        // Parse public key
        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(curveParams.getCurve().decodePoint(publicKeyBytes), curveParams);

        // Verify signature
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(false, publicKeyParams);
        BigInteger[] signature = new BigInteger[]{
                new BigInteger(1, Arrays.copyOfRange(signatureBytes, 0, signatureBytes.length / 2)),
                new BigInteger(1, Arrays.copyOfRange(signatureBytes, signatureBytes.length / 2, signatureBytes.length))
        };

        return signer.verifySignature(data.getBytes(), signature[0], signature[1]);
    }

    private static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static JsonObject genKeys() {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = generateKeyPair();

        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        // String privateKeyString = addLeadingByte(privateKey.getS().toString(16));
        String privateKeyString = privateKey.getS().toString(16);
        String publicKeyString = "04" + publicKey.getW().getAffineX().toString(16) +
                publicKey.getW().getAffineY().toString(16);

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("public_key", publicKeyString);
        jsonObject.addProperty("secret_key", privateKeyString);

        return jsonObject;
    }
}
