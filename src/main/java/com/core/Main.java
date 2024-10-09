package com.core;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import com.core.mainStructs.Transaction;
import com.core.server.Server;
import com.core.server.ServerConnect;


public class Main {
    public static Blockchain blockchain = new Blockchain();

    private static BlockingQueue<Transaction> transactionsQueue = new LinkedBlockingQueue<>();
    private static BlockingQueue<Transaction> transactionsQueueOK = new LinkedBlockingQueue<>();
    public static BlockingQueue<Transaction> transactionsNetwork = new LinkedBlockingQueue<>();

    public static int index;
    public static String previousHash;
    public static int key;

    public static int statuspirntblock = 0;

    public static int PORT_TO_START = 8080;

    public static void main(String[] args) {
        runServer();
        runProcessor();
        runNetworkManager();
        System.out.println("Main Modules Start... OK");
        ServerConnect.searchNodes();
        ServerConnect.connectNodes();
    }

    public static void runServer() {
        try {
        Thread server = new Thread(new Server(blockchain, transactionsQueue, transactionsQueueOK));
        server.start();
        System.out.println("Starting Server... OK");
        } catch (Exception e) {
            e.printStackTrace();

        }
    }

    public static void runProcessor() {
        Thread processor = new Thread(new ProcessorTransactions(transactionsQueue, transactionsQueueOK, transactionsNetwork));
        processor.start();
        System.out.println("Starting Processor Transaction... OK");
    }

    public static void runNetworkManager() {
        Thread networkManager = new Thread(new NetworkManager(transactionsNetwork));
        networkManager.start();
        System.out.println("Starting Network Manager... OK");
    }

    // public static void runNodesConnection() {
    //     Thread nodes = new Thread(new ServerConnect(transactionsQueue));
    //     nodes.start();
    // }
}
