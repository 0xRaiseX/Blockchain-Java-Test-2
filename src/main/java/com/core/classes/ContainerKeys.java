package com.core.classes;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import com.google.gson.JsonObject;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jce.spec.ECPublicKeySpec;


public class ContainerKeys {

    public JsonObject genKeys() {
        Security.addProvider(new BouncyCastleProvider());

        try {
            // Генерация ключевой пары
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
            keyPairGenerator.initialize(getECParameterSpec());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Приватный и публичный ключи
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
            
            
            // Представление ключей в виде строк
            String privateKeyStr = privateKey.getD().toString(16); // Using D for private key
            String publicKeyStr = new BigInteger(1, publicKey.getQ().getEncoded(false)).toString(16);
            if (publicKeyStr.length() > 128) {
                publicKeyStr = publicKeyStr.substring(1);
            }

            System.out.println("Приватный ключ: " + privateKeyStr + " " + privateKeyStr.length());
            System.out.println("Публичный ключ: " + publicKeyStr + " " + publicKeyStr.length());

            String walletAddressExample = generateWalletAddress(publicKeyStr);
            System.out.println("Адрес кошелька: " + walletAddressExample);

            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("publicKey", publicKeyStr);
            jsonObject.addProperty("secretKey", privateKeyStr);
 
            return jsonObject;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static ECParameterSpec getECParameterSpec() {
        return ECNamedCurveTable.getParameterSpec("secp256k1");
    }

        
    public static boolean verifySignature(String publicKeyStr, String data, String signature) {
        try {
            byte[] publicKeyBytes = new BigInteger(publicKeyStr, 16).toByteArray();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(data.getBytes());

            byte[] signatureBytes = new BigInteger(signature, 16).toByteArray();

            return ecdsaVerify.verify(signatureBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    
      public static String generateWalletAddress(String publicKeyHex) throws NoSuchAlgorithmException {
        // Преобразование hex-строки в байты
        byte[] publicKey = Hex.decode(publicKeyHex);

        // Хеширование публичного ключа с использованием Keccak-256
        MessageDigest keccakDigest = new Keccak.Digest256();
        byte[] keccakHash = keccakDigest.digest(publicKey);

        // Взятие последних 20 байтов
        byte[] walletAddressBytes = new byte[20];
        System.arraycopy(keccakHash, keccakHash.length - 20, walletAddressBytes, 0, 20);

        // Преобразование в шестнадцатеричную строку
        return "0x" + Hex.toHexString(walletAddressBytes);
    }


    public static boolean verifyECDSASignature(String publicKeyHex, String data, String signatureHex) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            byte[] publicKeyBytes = Hex.decode(publicKeyHex);
            // BigInteger publicKeyBigInt = new BigInteger(1, publicKeyBytes);

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
                // byte[] signatureBytes = hexStringToByteArray(signatureHex);
                byte[] signatureBytes = Hex.decode(signatureHex);

                if (signatureBytes == null) {
                    System.err.println("Ошибка: Некорректный формат подписи.");
                    return false;
                }
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

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }

    public static byte[] hexStringToByteArray(String hex) {
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


    // private String convertToBase64(byte[] key) {
    //     return Base64.getEncoder().encodeToString(key);
    // }


    // // Метод для преобразования массива байт в строку hex
    // private String bytesToHex(byte[] bytes) {
    //     StringBuilder result = new StringBuilder();
    //     for (byte b : bytes) {
    //         result.append(String.format("%02x", b));
    //     }
    //     return result.toString();
    // }

    // // Подпись данных с использованием приватного ключа
    // public static byte[] signData(String data, PrivateKey privateKey) throws Exception {
    //     Signature signature = Signature.getInstance("SHA256withECDSA");
    //     signature.initSign(privateKey);
    //     signature.update(data.getBytes());
    //     return signature.sign();
    // }

    // // Верификация подписи данных с использованием публичного ключа
    // public static boolean verifySignature(String data, byte[] signature, PublicKey publicKey) throws Exception {
    //     Signature verifier = Signature.getInstance("SHA256withECDSA");
    //     verifier.initVerify(publicKey);
    //     verifier.update(data.getBytes());
    //     return verifier.verify(signature);
    // }

    //    // Преобразование ключа в строку
    // public String convertKeyToString(java.security.Key key) {
    //     byte[] keyBytes = key.getEncoded();
    //     return Base64.getEncoder().encodeToString(keyBytes);
    // }

    // // Восстановление приватного ключа из строки
    // public PrivateKey convertStringToPrivateKey(String privateKeyString) throws Exception {
    //     byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
    //     KeyFactory keyFactory = KeyFactory.getInstance("EC");
    //     PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    //     return keyFactory.generatePrivate(keySpec);
    // }

    // // Восстановление публичного ключа из строки
    // public PublicKey convertStringToPublicKey(String publicKeyString) throws Exception {
    //     System.out.println("PUBLIC KEY " + publicKeyString);
    //     byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
    //     KeyFactory keyFactory = KeyFactory.getInstance("EC");
    //     X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
    //     return keyFactory.generatePublic(keySpec);
    // }
    
// }
