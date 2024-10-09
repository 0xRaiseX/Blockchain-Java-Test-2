package com.core.mainStructs;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import org.rocksdb.RocksDB;

import com.core.classes.Database;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;


public class Block {
    private int index;
    private long timestamp;
    private String validator;
    private String previousHash;
    private String hash;
    private List<Transaction> transactions;

    public Block(int index, long timestamp, List<Transaction> transactions, String previousHash) {
        this.index = index;
        this.timestamp = timestamp;
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.hash = calculateHash();
        this.validator = "main";
    }

    private String calculateHash() {
        try {
            StringBuilder dataToHash = new StringBuilder();
            dataToHash.append(index);
            dataToHash.append(timestamp);
            dataToHash.append(previousHash);

            for (Transaction transaction : transactions) {
                dataToHash.append(transaction.getSender());
                dataToHash.append(transaction.getRecipient());
                dataToHash.append(transaction.getAmount());
            }

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
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void saveBlock() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String blockJson = gson.toJson(this);

        try (RocksDB db = Database.openDatabase()) {
            System.out.println("Block build complite: " + index);
            byte[] key = String.valueOf(index).getBytes();
            byte[] value = blockJson.getBytes();
            db.put(key, value);

        } catch (Exception e) {

        }
    }
    
    public static Block fromByteArray(byte[] byteArray) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(byteArray);
            ObjectInput in = new ObjectInputStream(bis)) {
                return (Block) in.readObject();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
                return null;
            } 
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        return stringBuilder.toString();
    }
    
    public String getHash() {
        return hash;
    }
    public int getIndex(){
        return index;
    }
    public double getTimestamp(){
        return timestamp;
    }
    public String getPreviousHash(){
        return previousHash;
    }
    public List<Transaction> getTransactions(){
        return transactions;
    } 
    public String getValidator() {
        return validator;
    }
}
