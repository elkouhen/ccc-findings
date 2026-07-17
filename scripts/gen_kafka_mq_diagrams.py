"""Génère les diagrammes Draw.io (direct + cccr) pour microservices-kafka-mq.

Reproductible : régénère `reports/assets/microservices-kafka-mq-{cccr,direct}.drawio`
depuis un inventaire déclaré. Le HTML des étiquettes est échappé pour XML,
conformément au format mxfile attendu par drawio.
"""
from __future__ import annotations

import html
from xml.sax.saxutils import escape as xml_escape


def htext(text: str) -> str:
    """Échappe un texte dynamique destiné au HTML de l'étiquette."""
    return html.escape(text, quote=False)


def attr(value: str) -> str:
    """Échappe pour l'attribut XML toute la chaîne HTML (tags inclus)."""
    return xml_escape(value, {'"': "&quot;"})


def service_node(node_id: str, x: int, y: int, title: str, port: str, lines: list[str]) -> str:
    body = "<br>".join(htext(l) for l in lines)
    label = f"<b>{htext(title)}</b><br>:{htext(port)}<br><br>{body}"
    return (
        f'<mxCell id="{node_id}" value="{attr(label)}" '
        f'style="rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;'
        f'verticalAlign=top;fontSize=11;" vertex="1" parent="1">'
        f'<mxGeometry x="{x}" y="{y}" width="240" height="180" as="geometry"/></mxCell>'
    )


def topic_node(node_id: str, x: int, y: int, name: str, types: list[str]) -> str:
    label = f"<b>Kafka topic</b><br>{htext(name)}<br><i>{htext(' / '.join(types))}</i>"
    return (
        f'<mxCell id="{node_id}" value="{attr(label)}" '
        f'style="shape=cylinder3;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;'
        f'size=15;fontSize=11;" vertex="1" parent="1">'
        f'<mxGeometry x="{x}" y="{y}" width="120" height="80" as="geometry"/></mxCell>'
    )


def edge(eid: str, src: str, dst: str, label: str, kind: str) -> str:
    style = (
        "edgeStyle=orthogonalEdgeStyle;html=1;fontSize=11;strokeColor=#82b366;strokeWidth=2;"
        if kind == "kafka"
        else "edgeStyle=orthogonalEdgeStyle;html=1;dashed=1;fontSize=11;strokeColor=#9673a6;strokeWidth=2;"
    )
    return (
        f'<mxCell id="{eid}" value="{attr(htext(label))}" style="{style}" '
        f'edge="1" parent="1" source="{src}" target="{dst}">'
        f'<mxGeometry relative="1" as="geometry"/></mxCell>'
    )


def note(node_id: str, x: int, y: int, text: str, color: str = "#7f6fb0") -> str:
    label = htext(text)
    return (
        f'<mxCell id="{node_id}" value="{attr(label)}" '
        f'style="text;html=1;align=left;fontSize=10;fontColor={color};" vertex="1" parent="1">'
        f'<mxGeometry x="{x}" y="{y}" width="360" height="30" as="geometry"/></mxCell>'
    )


def build(title: str, order_lines: list[str], invoicing_lines: list[str], audit_note: str) -> str:
    cells = [
        service_node("order", 40, 130, "microservice-order", "8080", order_lines),
        topic_node("topic_order", 350, 170, "order", ["pub: Order", "cons: Invoice"]),
        service_node("invoicing", 530, 130, "microservice-invoicing", "8081", invoicing_lines),
        edge("e1", "order", "topic_order", "kafka · produce (Order)", "kafka"),
        edge("e2", "topic_order", "invoicing", "kafka · consume (Invoice)", "kafka"),
        note("n1", 40, 330, audit_note, "#B85450"),
        note("n2", 40, 365, "Aucun client HTTP (RestTemplate/WebClient/Feign) -> aucune arête HTTP inter-services."),
    ]
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<mxfile host="cccr">'
        f'<diagram name="{attr(htext(title))}">'
        '<mxGraphModel dx="900" dy="600" grid="1" gridSize="10" guides="1" tooltips="1" '
        'connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="900" pageHeight="450" '
        'math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
        f'{"".join(cells)}</root></mxGraphModel></diagram></mxfile>'
    )


DIRECT_ORDER = [
    "HTTP servi (Spring MVC) :",
    "  POST /api/order",
    "  GET  /api/order",
    "Spring Data REST (base /) :",
    "  /order (CRUD) - OrderRepository",
    "  /users (CRUD) - UserRepository",
    "Kafka : produit 'order'",
]
DIRECT_INVOICING = [
    "HTTP servi (Spring MVC) :",
    "  ANY /",
    "  GET /{id}",
    "Kafka : consomme 'order'",
    "Mongo : aucun (JPA/MySQL)",
]
CCCR_ORDER = [
    "POST /api/order - GET /api/order",
    "SDR /order (CRUD) - detecte",
    "SDR /users (CRUD) - detecte",
    "[framework] actuator, swagger-ui",
    "Kafka : publie order (Order)",
]
CCCR_INVOICING = [
    "ANY / - GET /{id}",
    "[framework] actuator",
    "Kafka : consomme order (Invoice)",
]

DIRECT = build(
    "microservices-kafka-mq - analyse directe (reference)",
    DIRECT_ORDER,
    DIRECT_INVOICING,
    "Audit direct : le producteur envoie Order, le consommateur deserialise en Invoice.",
)
CCCR = build(
    "microservices-kafka-mq - inventaire cccr (post-fix /users)",
    CCCR_ORDER,
    CCCR_INVOICING,
    "cccr audit : 'order publie Order mais consomme Invoice' (medium).",
)


def main() -> None:
    base = "reports/assets/microservices-kafka-mq"
    for suffix, content in (("-direct.drawio", DIRECT), ("-cccr.drawio", CCCR)):
        with open(f"{base}{suffix}", "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"wrote {base}{suffix}")


if __name__ == "__main__":
    main()
