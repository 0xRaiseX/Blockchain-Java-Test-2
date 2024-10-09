package com.core;

import com.core.classes.Config;
import com.core.mainStructs.Block;

public class ProcessorConsensys extends Thread{
    private int blockSize = Config.blockSize;
    
    public void run() {
        while (true) {
            if (Blockchain.transactions.size() > blockSize) {
                Main.index += 1;
                Block block = new Block(Main.index, Blockchain.getTimestamp(), Blockchain.transactions, Main.previousHash);
                Main.previousHash = block.getHash();
                block.saveBlock();
                Blockchain.transactions.clear();
            }
            try {
            Thread.sleep(1000);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
