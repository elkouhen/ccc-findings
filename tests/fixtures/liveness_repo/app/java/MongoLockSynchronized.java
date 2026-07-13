package com.example.app;

import org.bson.Document;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;

public class MongoLockSynchronized {

    private final Object lock = new Object();
    private final MongoTemplate mongoTemplate;

    public MongoLockSynchronized(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    // mauvais : findAndModify sous un moniteur JVM tenu
    public Document acquireBad(Query query, Update update) {
        synchronized (lock) {
            return mongoTemplate.findAndModify(query, update, FindAndModifyOptions.options().returnNew(true), Document.class);
        }
    }

    // bon : l'appel Mongo se fait hors du bloc synchronized
    public Document acquireGood(Query query, Update update) {
        Document result = mongoTemplate.findAndModify(query, update, FindAndModifyOptions.options().returnNew(true), Document.class);
        synchronized (lock) {
            return result;
        }
    }
}
