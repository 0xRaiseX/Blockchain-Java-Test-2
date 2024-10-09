package com.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.rocksdb.RocksIterator;
import com.core.mainStructs.Transaction;

import com.core.classes.Database;
import com.core.mainStructs.Block;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;


public class Blockchain {
    public static Block lastBlock;
    public static List<Transaction> transactions = new ArrayList<>();

    public Blockchain() {
        RocksDB.loadLibrary();
        loadDataBase();
    }

    private void loadDataBase() {
        loadKeys();
        try (RocksDB db = Database.openDatabase()) {
            byte[] key = String.valueOf(Main.key).getBytes();
            byte[] value = db.get(key);

            String keyString = new String(key);
            String valueString = new String(value);

            JsonObject json = JsonParser.parseString(valueString).getAsJsonObject();

            if (Main.statuspirntblock == 1) {
                System.out.println("Key: " + keyString + ", Value: " + valueString);
            }
            Main.index = Integer.parseInt(keyString);
            Main.previousHash = json.get("hash").getAsString();
        } catch (RocksDBException e) {
            e.printStackTrace();
        }
    }

    public void printLastBlock() {
        try (RocksDB db = Database.openDatabase()) {
            byte[] key = String.valueOf(Main.key).getBytes();
            byte[] value = db.get(key);

            String keyString = new String(key, StandardCharsets.UTF_8);
            String valueString = new String(value, StandardCharsets.UTF_8);

            // JsonObject json = JsonParser.parseString(valueString).getAsJsonObject();

            System.out.println("Key: " + keyString + ", Value: " + valueString);
           

        } catch (RocksDBException e) {
            e.printStackTrace();
        }
    }

    public void loadKeys() {
         try (RocksDB db = Database.openDatabase()) {

            try (final RocksIterator iterator = db.newIterator()) {
                iterator.seekToFirst();
                
                int maxKey = 0;
                int keyInt = 0;

                while (iterator.isValid()) {
                    byte[] key = iterator.key();
                    String keyString = new String(key);
                    keyInt = Integer.parseInt(keyString);
                    if (keyInt > maxKey) {
                        maxKey = keyInt;
                    }
                    iterator.next();
                }
                Main.key = maxKey;
            }
        } catch (RocksDBException e) {
            e.printStackTrace();
        }
    }

    public String getBlock(int index) {
        long start = System.currentTimeMillis();

        try (RocksDB db = Database.openDatabase()) {

            byte[] key = String.valueOf(index).getBytes();
            byte[] retrievedValue = db.get(key);

            if (retrievedValue != null) {
                // Block block = Block.fromByteArray(retrievedValue);
                String valueString = new String(retrievedValue);
                System.out.println(System.currentTimeMillis() - start);
                return valueString;

            } else {
                return null;
            }

        } catch (RocksDBException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String getTransactions() {
        String dataBlock = getBlock(Main.index);

        if (dataBlock != null) {

            JsonObject jsonBlock = JsonParser.parseString(dataBlock).getAsJsonObject();
            JsonArray JsonTransactions = jsonBlock.get("transactions").getAsJsonArray();
            return JsonTransactions.toString();
        } else {
            return "Key not Found";
        }
    }

    public static long getTimestamp() {
        return System.currentTimeMillis();
    }

    public void getBalance() {

    }
}


