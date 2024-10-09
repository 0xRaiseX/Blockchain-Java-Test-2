package com.core.mainStructs;

import java.net.URI;
import java.net.URISyntaxException;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

public class Node {
    private String ip;
    private WebSocketClient webSocketClient;
    private int port;
    private String state = "NOT CONNECTED";

    public Node(String ip, int port) {
        this.ip = ip;
        this.port = port;
    }

    public void connect() {
        String serverUri = "ws://localhost:" + port + "/ws";

        try {
            webSocketClient = new WebSocketClient(new URI(serverUri)) {
                @Override
                public void onOpen(ServerHandshake handshakedata) {
                    System.out.println("WebSocket connection opened");
                }

                @Override
                public void onMessage(String message) {
                    System.out.println("Received message: " + message);
                }

                @Override
                public void onClose(int code, String reason, boolean remote) {
                    System.out.println("WebSocket connection closed. Code: " + code + ", Reason: " + reason);
                }

                @Override
                public void onError(Exception ex) {
                    System.err.println("WebSocket error: " + ex.getMessage());
                }
            };

            webSocketClient.connect();

        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    public int getPort() {
        return port;
    }

    public void send(String message) {
        if (webSocketClient != null && webSocketClient.isOpen()) {
           webSocketClient.send(message);
        } else {
            System.err.println("Websocket client is not open.");
        }
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }
}


