package com.example.app;

import java.util.HashMap;
import java.util.Map;

public class HashMapWriter {

    public void store(String key, String value) {
        Map<String, String> values = new HashMap<>();
        values.put(key, value);
    }
}
