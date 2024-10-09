package com.core.mainStructs;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import com.google.gson.JsonObject;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;

public class TransactionSTAKE {
    private String walletAddres;
    private String amountStake;
    private String timestamp; // время создания транзакции 

    private String hash; // хеш транзакции
    private String fee; // коммисия

    private String state; 

    private ChannelHandlerContext ctx;
    private FullHttpRequest request;
    private String signature;

    private String messageState;
    public int typeTransaction = 0;

    public TransactionSTAKE(String walletAddres, String amountStake) {
        this.walletAddres = walletAddres;
        this.amountStake = amountStake;
    }

    public void calculateHash() {
        try {
            StringBuilder dataToHash = new StringBuilder();
            dataToHash.append(walletAddres);
            dataToHash.append(amountStake);
            dataToHash.append(timestamp);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(dataToHash.toString().getBytes());

            StringBuilder hexString = new StringBuilder();
            for (byte hashByte : hashBytes) {
                String hex = Integer.toHexString(0xff & hashByte);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            hash = hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    public String getWalletAddres(){
        return walletAddres;
    }

    public String getAmountStake() {
        return amountStake;
    }

    public String getTimestamp(){
        return timestamp;
    }


    public String getHash() {
        return hash;
    }

    public String getfee() {
        return fee;
    }
    public String getState() {
        return state;
    }


    public ChannelHandlerContext getCtx() {
        return ctx;
    }

    public FullHttpRequest getRequest() {
        return request;
    }

    public String getSignature() {
        return signature;
    }


    public String getMessageState() {
        return messageState;
    }

    public int getTypeTransaction() {
        return typeTransaction;
    }


    public void setFee(double fee) {
        this.fee = String.valueOf(fee);
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }
    
    public void setState(String state) {
        this.state = state;
    }

    public void setCtx(ChannelHandlerContext ctx) {
        this.ctx = ctx;
    }

    public void setRequest(FullHttpRequest request) {
        this.request = request;
    } 

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String toString() {
        JsonObject object = new JsonObject();
        object.addProperty("walletAddres", walletAddres);
        object.addProperty("amountStake", amountStake);
        
        String json = object.toString();
        return json;
    }

    public JsonObject getJson() {
        JsonObject object = new JsonObject();
        object.addProperty("walletAddres", walletAddres);
        object.addProperty("amountStake", amountStake);
        
        return object;
    }

    public void buildMessage(int statusCode, String text) {
        JsonObject jsonObject = new JsonObject();

        jsonObject.addProperty("code", statusCode);
        jsonObject.addProperty("message", text);
        String message = jsonObject.toString();
        this.messageState = message;
    }
}

