import azure.functions as func
from azure.functions import AsgiMiddleware
from main import app as fastapi_app

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="{*route}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    # route to wszystko po /api/
    route = req.route_params.get("route", "")
    if not route.startswith("/"):
        route = "/" + route

    # baza bez /api/...
    base = req.url.split("/api", 1)[0]
    new_url = base + route

    headers = dict(req.headers)
    headers["x-forwarded-prefix"] = "/api"

    new_req = func.HttpRequest(
        method=req.method,
        url=new_url,
        headers=headers,
        params=req.params,
        route_params=req.route_params,
        body=req.get_body(),
    )


    return AsgiMiddleware(fastapi_app).handle(new_req, context)
