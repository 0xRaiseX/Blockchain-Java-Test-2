package com.core;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;

import org.bouncycastle.util.encoders.Hex;

import com.core.classes.Config;
import com.core.classes.ContainerECDSA;
import com.core.mainStructs.Block;
import com.core.mainStructs.Transaction;
import com.google.gson.JsonObject;


public class ProcessorTransactions extends Thread {
    private BlockingQueue<Transaction> transactionsQueue;
    private BlockingQueue<Transaction> transactionsQueueOK;
    private BlockingQueue<Transaction> transactionsNetwork;
    private ContainerECDSA ecdsa = new ContainerECDSA();

    public ProcessorTransactions(BlockingQueue<Transaction> transactionsQueue, BlockingQueue<Transaction> transactionsQueueOK, BlockingQueue<Transaction> transactionsNetwork) {
        this.transactionsQueue = transactionsQueue;
        this.transactionsQueueOK = transactionsQueueOK;
        this.transactionsNetwork = transactionsNetwork;
    }

    private long getTimestamp() {
        return System.currentTimeMillis();
    }

    public void run() {
        while (true) {
            try {
                Transaction transaction = transactionsQueue.take();

                if (transaction.getTypeTransaction() == 0) {
                    System.out.println("New transaction: node");
                } else {
                    System.out.println("New transaction: api");
                }
                if (transaction.getSender() == null) {
                    transaction.setState("Error");
                    transaction.buildMessage(1, "Sender cannot be empty");
                }

                if (transaction.getRecipient() == null) {
                    transaction.setState("Error");
                    transaction.buildMessage(1, "Recipient cannot be empty");
                }

                if (transaction.getAmount() == null) {
                    transaction.setState("Error");
                    transaction.buildMessage(1, "Amount cannot be empty");
                }

                if (transaction.getSignature() == null) {
                    transaction.setState("Error");
                    transaction.buildMessage(1, "Signature cannot be empty");
                }

                JsonObject jsonObject = new JsonObject();
                jsonObject.addProperty("sender", transaction.getSender());
                jsonObject.addProperty("recipient", transaction.getRecipient());
                jsonObject.addProperty("amount", transaction.getAmount());
                
                String dataTransaction = jsonObject.toString();
                

                byte[] signature = ecdsa.signMessage(ecdsa.privateKeyFromHex(transaction.getRecipient()), dataTransaction);
                boolean verify2 = ecdsa.verifyECDSASignature(transaction.getSender(), dataTransaction, Hex.toHexString(signature));
                System.out.println("verify 2: " + verify2);

                // boolean verify = ecdsa.verifyECDSASignature(transaction.getSender(), dataTransaction, transaction.getSignature());
                boolean verify = ecdsa.verifyECDSASignature(transaction.getSender(), dataTransaction, transaction.getSignature());
                // boolean isValid = ContainerKeys.verifyECDSASignature(transaction.getSender(), dataTransaction, request.getSignature());
                // boolean isValid = ContainerKeys.verifySignature(transaction.getSender(), dataTransaction, request.getSignature());
                System.out.println("verify: " + verify);
                transaction.setTimestamp(String.valueOf(getTimestamp()));
                transaction.setFee(0);
                transaction.calculateHash();

                if (transaction.getState() == null) {
                    if (verify) {
                        transaction.setState("Success");
                        Blockchain.transactions.add(transaction);
                        transaction.buildMessage(0, "OK");
                        transactionsNetwork.add(transaction);
                        System.out.println("VERIFY VALID");
                    } else {
                        transaction.setState("Error");
                        transaction.buildMessage(0, "Signature error");
                    }
                }
                
                if (transaction.getTypeTransaction() == 1) {
                    transactionsQueueOK.add(transaction);
                }

                // if (Blockchain.transactions.size() > blockSize) {
                //     Main.index += 1;
                //     Block block = new Block(Main.index, getTimestamp(), Blockchain.transactions, Main.previousHash);
                //     Main.previousHash = block.getHash();
                //     block.saveBlock();
                //     Blockchain.transactions.clear();
                // }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
