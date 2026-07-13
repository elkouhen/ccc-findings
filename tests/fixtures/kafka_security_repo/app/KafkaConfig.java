package com.example.app;

import java.util.Properties;
import org.apache.kafka.clients.CommonClientConfigs;

public class KafkaConfig {

    public Properties badSaslCredentials() {
        Properties props = new Properties();
        props.put("sasl.jaas.config",
                "org.apache.kafka.common.security.plain.PlainLoginModule required "
                        + "username=\"admin\" password=\"supersecret\";");
        return props;
    }

    public Properties goodSaslCredentials(String password) {
        Properties props = new Properties();
        props.put("sasl.jaas.config",
                "org.apache.kafka.common.security.plain.PlainLoginModule required "
                        + "username=\"admin\" password=\"" + password + "\";");
        return props;
    }

    public Properties badPlaintextProtocol() {
        Properties props = new Properties();
        props.put("security.protocol", "PLAINTEXT");
        return props;
    }

    public Properties badPlaintextProtocolConstant() {
        Properties props = new Properties();
        props.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "PLAINTEXT");
        return props;
    }

    public Properties goodSaslSslProtocol() {
        Properties props = new Properties();
        props.put("security.protocol", "SASL_SSL");
        return props;
    }
}
