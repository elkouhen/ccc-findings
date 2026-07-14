# BACKLOG-6 — Detect Kafka publishers using `send(message)` via `MessageBuilder`

## [x] N1 : Infer Spring Kafka producers built through `MessageBuilder`

**Files** : `src/ccc_radar/scanner.py`, `tests/test_kafka_endpoints.py`,
`tests/fixtures/kafka_repo/app/java/MessageBuilderProducer.java`,
`docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`.

**Description** : complete the Kafka inventory to detect Spring publishers
built in two steps (`MessageBuilder.withPayload(...).setHeader(TOPIC, ...)`
then `kafkaTemplate.send(message)`), currently missed because existing Semgrep
rules cover `send(topic, ...)`, `sendDefault(...)`, and `ProducerRecord`, but
not the `send(Message<?>)` overload.

**AC** :
- `cccr endpoints` reports a Kafka producer for `kafkaTemplate.send(message)`
  when `message` was built with `MessageBuilder` and a `TOPIC`/
  `KafkaHeaders.TOPIC` header;
- the topic is resolved to a literal, Spring placeholder, or `@Value` field
  when possible; otherwise it remains dynamic and is never guessed;
- Kafka tests cover at least one literal topic and one topic resolved through
  `@Value`.
