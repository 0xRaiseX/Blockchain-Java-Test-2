package com.core.classes;

import org.rocksdb.Options;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;

public class Database {
    public static RocksDB openDatabase() throws RocksDBException{
        Options options = new Options().setCreateIfMissing(true);
        return RocksDB.open(options, Config.pathDB);
    }


    public static RocksDB openDatabaseWallet() throws RocksDBException{
        Options options = new Options().setCreateIfMissing(true);
        return RocksDB.open(options, Config.pathDB);
    }
    
}
