package com.core.server;

import java.util.concurrent.BlockingQueue;

import com.core.Main;
import com.core.classes.Config;
import com.core.mainStructs.Node;
import com.core.mainStructs.Transaction;

public class ServerConnect {
    // private BlockingQueue<TransactionRequest> transactionsQueue;

    public ServerConnect(BlockingQueue<Transaction> transactionsQueue) {
        // this.transactionsQueue = transactionsQueue;
    }

    public static void searchNodes() {
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
            }

        }
    }

    public static void connectNodes() {
        for (Node node : Config.nodes) {
            if (node.getState().equals("NOT CONNECTED")) {
                node.connect();
                node.setState("CONNECTED");
            }
        }
    }

    public static void sendNodes(String message) {
        for (Node node : Config.nodes) {
            node.send(message);
        }
    }
}