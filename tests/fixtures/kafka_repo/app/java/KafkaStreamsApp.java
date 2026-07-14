package com.example.app;

import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.kstream.*;
import org.springframework.context.annotation.Bean;
import org.springframework.kafka.annotation.EnableKafkaStreams;
import org.springframework.kafka.support.serializer.JsonSerde;

import java.time.Duration;

public class KafkaStreamsApp {

    @Bean
    public KStream<Long, Order> stream(StreamsBuilder builder) {
        JsonSerde<Order> orderSerde = new JsonSerde<>(Order.class);
        KStream<Long, Order> stream = builder
                .stream("payment-orders", Consumed.with(Serdes.Long(), orderSerde));

        KStream<Long, Order> joined = stream.join(
                builder.stream("stock-orders"),
                orderManageService::confirm,
                JoinWindows.of(Duration.ofSeconds(10)),
                StreamJoined.with(Serdes.Long(), orderSerde, orderSerde));

        joined.peek((k, o) -> LOG.info("Output: {}", o)).to("orders");

        return stream;
    }

    @Bean
    public KTable<Long, Order> table(StreamsBuilder builder) {
        KStream<Long, Order> materialized = builder
                .stream("orders", Consumed.with(Serdes.Long(), new JsonSerde<>(Order.class)));
        return materialized.toTable();
    }
}
