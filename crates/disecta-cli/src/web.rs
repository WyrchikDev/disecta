use std::io::Read;
use std::io::{self, Cursor};

use disecta_core::{Binary, EXAMPLE_PE, Limits};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::{CliError, find_section, parse_address};

type Reply = Response<Cursor<Vec<u8>>>;
const PAGE_SIZE: usize = 256;

pub fn serve(port: u16, limits: Limits, verbose: bool) -> Result<(), CliError> {
    let server =
        Server::http(("127.0.0.1", port)).map_err(|error| io::Error::other(error.to_string()))?;
    let host = server.server_addr().to_string();
    let origin = format!("http://{host}");
    println!("Open {origin}");
    for mut request in server.incoming_requests() {
        let reply = route(&mut request, &host, &origin, limits);
        if let Err(error) = request.respond(reply)
            && verbose
        {
            eprintln!("HTTP response: {error}");
        }
    }
    Ok(())
}

fn route(request: &mut Request, host: &str, origin: &str, limits: Limits) -> Reply {
    if request_header(request, "Host") != Some(host) {
        return problem(403, "invalid host");
    }
    let url = request.url().to_owned();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    match (request.method(), path) {
        (&Method::Get, "/") => response(
            200,
            "text/html; charset=utf-8",
            include_bytes!("web/index.html"),
        ),
        (&Method::Get, "/style.css") => response(
            200,
            "text/css; charset=utf-8",
            include_bytes!("web/style.css"),
        ),
        (&Method::Get, "/app.js") => response(
            200,
            "text/javascript; charset=utf-8",
            include_bytes!("web/app.js"),
        ),
        (&Method::Get, "/example") => response(200, "application/octet-stream", EXAMPLE_PE),
        (&Method::Post, "/open" | "/disasm") => {
            if request_header(request, "Origin") != Some(origin)
                || request_header(request, "Content-Type") != Some("application/octet-stream")
                || request_header(request, "X-Disecta") != Some("1")
            {
                return problem(403, "request must come from the local workbench");
            }
            let Some(length) = request.body_length() else {
                return problem(411, "request needs a known content length");
            };
            if length > limits.file_bytes {
                return problem(413, "file exceeds the configured size limit");
            }
            let mut bytes = Vec::new();
            if request
                .as_reader()
                .take(length as u64)
                .read_to_end(&mut bytes)
                .is_err()
                || bytes.len() != length
            {
                return problem(400, "could not read the full file");
            }
            match analyze(path, query, &bytes, limits) {
                Ok(bytes) => response(200, "application/json", &bytes),
                Err(error) => {
                    let status = match error.kind {
                        "limit" => 413,
                        "io" | "output" => 500,
                        _ => 422,
                    };
                    problem(status, &error.message)
                }
            }
        }
        _ => problem(404, "resource not found"),
    }
}

fn analyze(path: &str, query: &str, bytes: &[u8], limits: Limits) -> Result<Vec<u8>, CliError> {
    let image = Binary::parse(bytes, limits)?;
    if path == "/open" {
        let metadata = image.metadata();
        let start = metadata
            .entry
            .and_then(|entry| {
                find_section(metadata, Some(entry))
                    .ok()
                    .map(|index| (index, Some(entry)))
            })
            .or_else(|| find_section(metadata, None).ok().map(|index| (index, None)));
        let page = start
            .map(|(index, address)| image.disassemble(index, address, PAGE_SIZE))
            .transpose()?;
        return Ok(serde_json::to_vec(
            &serde_json::json!({ "metadata": metadata, "page": page }),
        )?);
    }
    let parameters = query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .collect::<Vec<_>>();
    let value = |key| {
        parameters
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| *value)
    };
    let invalid = || CliError {
        kind: "address",
        message: "invalid disassembly parameters".into(),
        code: 3,
    };
    let section = value("section")
        .and_then(|section| section.parse::<usize>().ok())
        .ok_or_else(invalid)?;
    let start = value("start")
        .map(parse_address)
        .transpose()
        .map_err(|_| invalid())?;
    let page = image.disassemble(section, start, PAGE_SIZE)?;
    Ok(serde_json::to_vec(&page)?)
}

fn request_header<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    let mut headers = request
        .headers()
        .iter()
        .filter(|header| header.field.equiv(name));
    let header = headers.next()?;
    headers.next().is_none().then(|| header.value.as_str())
}

fn problem(status: u16, message: &str) -> Reply {
    response(
        status,
        "application/json",
        serde_json::json!({"error": message}).to_string().as_bytes(),
    )
}

fn response(status: u16, content_type: &str, body: &[u8]) -> Reply {
    let mut reply = Response::from_data(body).with_status_code(status);
    for (name, value) in [
        ("Content-Type", content_type),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        (
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    ] {
        if let Ok(header) = Header::from_bytes(name, value) {
            reply.add_header(header);
        }
    }
    reply
}
