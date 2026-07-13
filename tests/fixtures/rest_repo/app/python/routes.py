from fastapi import FastAPI

app = FastAPI()


@app.get("/orders/{order_id}")
def get_order(order_id: str):
    return None


@app.post("/orders")
def create_order():
    return None


@app.put("/orders/{order_id}")
def update_order(order_id: str):
    return None


@app.delete("/orders/{order_id}")
def delete_order(order_id: str):
    return None


@app.patch("/orders/{order_id}/status")
def patch_status(order_id: str):
    return None


@app.route("/orders/{order_id}/summary")
def get_summary(order_id: str):
    return None
