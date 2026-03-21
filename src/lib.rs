mod config;
mod do_state;
mod oauth;
mod proxy;
mod state;

use worker::*;

const DO_BINDING: &str = "SGPROXY_STATE";
const DO_SINGLETON: &str = "singleton";

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    match req.path().as_str() {
        "/" => Response::from_html(render_index("admin")),
        "/usage" => Response::from_html(render_index("usage")),
        "/favicon.ico" => Response::empty().map(|resp| resp.with_status(204)),
        path if path == "/v1" || path.starts_with("/v1/") || path.starts_with("/api/") => {
            let stub = singleton_stub(&env)?;
            stub.fetch_with_request(req).await
        }
        _ => Response::error("not found", 404),
    }
}

fn render_index(mode: &str) -> String {
    include_str!("web/index.html").replace("__SGPROXY_VIEW_MODE__", mode)
}

fn singleton_stub(env: &Env) -> Result<Stub> {
    env.durable_object(DO_BINDING)?
        .id_from_name(DO_SINGLETON)?
        .get_stub()
}
