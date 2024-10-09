package com.core.classes;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import com.core.mainStructs.Node;

public class Config {
    public static String pathDB = "B:/Core/Database";
    public static String pathDBWallet = "B:/Core/Database";
    public static int blockSize = 100;
    public static List<Node> nodes = new ArrayList<>();
    
    public static byte[] intToBytes(int value) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(value);
        return buffer.array();
    }
}
