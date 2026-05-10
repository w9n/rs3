use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use http::{HeaderValue, Method, Response, StatusCode};
use http_body_util::Full;

const INDEX_HTML: &str = include_str!("../ui/index.html");
const CONSOLE_JS: &str = include_str!("../ui/console.js");
const CONSOLE_CSS: &str = include_str!("../ui/console.css");
const FAVICON_SVG: &str = include_str!("../ui/favicon.svg");
const CSP: &str = "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'";

pub(crate) fn ui_asset_response(method: &Method, path: &str) -> Option<Response<Full<Bytes>>> {
    if *method != Method::GET {
        return None;
    }

    let (content_type, body) = match path {
        "/" | "/ui" | "/ui/" => ("text/html; charset=utf-8", INDEX_HTML),
        "/ui/console.js" => ("text/javascript; charset=utf-8", CONSOLE_JS),
        "/ui/console.css" => ("text/css; charset=utf-8", CONSOLE_CSS),
        "/favicon.svg" | "/ui/favicon.svg" => ("image/svg+xml", FAVICON_SVG),
        _ => return None,
    };
    Some(asset_response(content_type, body))
}

fn asset_response(content_type: &'static str, body: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    response
}
