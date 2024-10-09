package com.core;

import java.util.HashMap;
import java.util.concurrent.BlockingQueue;

import com.core.classes.Config;
import com.core.mainStructs.Node;
import com.core.mainStructs.Transaction;
import com.core.server.ServerConnect;
import com.google.gson.JsonObject;

public class NetworkManager extends Thread {
    //Ожидает получения транзакций, а также оптравяет транзакция всем участникам сети
    //Регистрирует новые узлы в сети
    private BlockingQueue<Transaction> transactionsNetwork;
    private HashMap<Integer, Node> nodes = new HashMap<>();

    public NetworkManager(BlockingQueue<Transaction> transactionsNetwork) {
        this.transactionsNetwork = transactionsNetwork;
    }

    public static void createNode() {
        
    }

    public static void searchNodes() {
        System.out.println("Network manager: search nodes");
        if (Main.PORT_TO_START == 8080) {
            return;
        }

        for (int i = 8080; i < Main.PORT_TO_START; i ++) {

            if (Config.nodes.size() > 3) {
                break;
            }

            boolean flagConnect = true;

            for (Node node : Config.nodes) {
                if (node.getPort() == i) {
                    flagConnect = false;
                    continue;
                }
            }

            if (flagConnect) {
                System.out.println("CONNECT TO PORT " + i);
                Node node = new Node("ws://localhost:8080/ws", i);
                Config.nodes.add(node);
                
                // int maxValue = nodes.get();

                node.connect();
            }

        }
    }


    public void run() {
        while (true) {
            try {
                Transaction transaction = transactionsNetwork.take();
                System.out.println("Network manager: new transaction");
                JsonObject jsonObject = new JsonObject();
                jsonObject.add("transaction", transaction.getJson());
                jsonObject.addProperty("sender", Main.PORT_TO_START);
                

                ServerConnect.sendNodes(jsonObject.toString());
                
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            
        }
    }
}
