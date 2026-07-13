package com.example.app;

import org.springframework.kafka.support.serializer.ErrorHandlingDeserializer;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.Properties;

public class Deserialization {

    public void configureBadJsonDeserializer(JsonDeserializer<Object> deserializer) {
        deserializer.addTrustedPackages("*");
    }

    public void configureBadJsonDeserializerProps(Properties props) {
        props.put("spring.json.trusted.packages", "*");
    }

    public void configureGoodJsonDeserializer(JsonDeserializer<Object> deserializer) {
        deserializer.addTrustedPackages("com.example.events");
    }

    public Object readBad(InputStream stream) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(stream);
        return ois.readObject();
    }

    public byte[] readGoodNoDeserialize(InputStream stream) throws IOException {
        return stream.readAllBytes();
    }
}
