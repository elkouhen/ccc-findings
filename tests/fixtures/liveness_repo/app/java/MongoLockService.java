package com.example.app;

import org.bson.Document;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;

import java.util.concurrent.TimeUnit;

public class MongoLockService {

    private final MongoTemplate mongoTemplate;

    public MongoLockService(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    // mauvais : sondage bloquant sans timeout
    public Document acquireLockBusyWaitBad(Query query, Update update) throws InterruptedException {
        Document lock = null;
        while (lock == null) {
            lock = mongoTemplate.findAndModify(query, update, FindAndModifyOptions.options().returnNew(true), Document.class);
            Thread.sleep(200);
        }
        return lock;
    }

    // mauvais : même motif avec une boucle for et findOneAndUpdate (driver natif)
    public Document acquireLockForLoopBad(
            com.mongodb.client.MongoCollection<Document> collection,
            org.bson.conversions.Bson filter,
            org.bson.conversions.Bson update) throws InterruptedException {
        for (int attempt = 0; attempt < 10; attempt++) {
            Document lock = collection.findOneAndUpdate(filter, update);
            if (lock != null) {
                return lock;
            }
            Thread.sleep(500);
        }
        return null;
    }

    // bon : une seule tentative, pas de boucle de sondage
    public Document acquireLockOnceGood(Query query, Update update) {
        return mongoTemplate.findAndModify(query, update, FindAndModifyOptions.options().returnNew(true), Document.class);
    }

    // bon : boucle de retry avec sleep, mais sans rapport avec Mongo (ne doit pas
    // être signalée comme un verrou pessimiste)
    public void unrelatedRetryLoopGood() throws InterruptedException {
        int attempts = 0;
        while (attempts < 5) {
            attempts++;
            Thread.sleep(100);
        }
    }
}
