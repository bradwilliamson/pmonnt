use reqwest::blocking::Client;
use std::env;
use std::time::Duration;

fn get_key() -> Option<String> {
    env::var("PMONNT_MB_API_KEY")
        .ok()
        .or_else(|| env::var("PMONNT_MALWAREBAZAAR_KEY").ok())
}

fn post_and_print(form: &[(&str, &str)], raw: bool) -> Result<(), Box<dyn std::error::Error>> {
    let api_key = match get_key() {
        Some(k) => k,
        None => {
            eprintln!("No API key found in PMONNT_MB_API_KEY or PMONNT_MALWAREBAZAAR_KEY");
            return Ok(());
        }
    };

    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;
    let mb_url = std::env::var("MB_BASE_URL")
        .unwrap_or_else(|_| "https://mb-api.abuse.ch/api/v1/".to_string());
    let resp = client
        .post(mb_url)
        .header("Auth-Key", api_key)
        .form(form)
        .send()?;

    println!("HTTP: {}", resp.status());
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if raw {
        // Print raw body
        let text = resp.text()?;
        println!("--- RAW JSON ---\n{}", text);
        return Ok(());
    }
    if content_type.contains("application/json") {
        let json: serde_json::Value = resp.json()?;
        let qs = json
            .get("query_status")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!("query_status: {}", qs);
        let data = json
            .get("data")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        println!("entries: {}", data.len());
        for entry in data.iter() {
            let sha = entry
                .get("sha256_hash")
                .or_else(|| entry.get("sha256"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let sig = entry
                .get("signature")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let first = entry
                .get("first_seen")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            println!("{} {} {}", &sha, &sig, &first);
        }
    } else {
        println!("Non-JSON response; content-type={}", content_type);
    }

    Ok(())
}

fn print_usage() {
    eprintln!("Usage: pmonnt-mb-debug <command>");
    eprintln!("Commands:");
    eprintln!("  get-info <sha256>");
    eprintln!("  recent [hours]");
    eprintln!("  tag <tag> [limit]");
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = match args.next() {
        Some(c) => c,
        None => {
            print_usage();
            return;
        }
    };

    // Collect remaining args and detect --raw flag
    let mut rest: Vec<String> = std::iter::once(cmd.clone()).chain(args).collect();
    let raw = rest.iter().any(|s| s == "--raw");
    // Remove raw flag from args list
    rest.retain(|s| s != "--raw");

    if rest.is_empty() {
        print_usage();
        return;
    }

    let verb = rest.remove(0);
    match verb.as_str() {
        "get-info" => {
            if let Some(sha) = rest.first() {
                let _ = post_and_print(&[("query", "get_info"), ("hash", sha)], raw);
            } else {
                eprintln!("get-info requires <sha256>");
            }
        }
        "recent" => {
            let hours = rest.first().cloned().unwrap_or_else(|| "48".to_string());
            let _ = post_and_print(&[("query", "recent_detections"), ("hours", &hours)], raw);
        }
        "recent-additions" => {
            let sel = rest.first().map(|s| s.as_str()).unwrap_or("time");
            let selector = if sel == "100" { "100" } else { "time" };
            let _ = post_and_print(&[("query", "get_recent"), ("selector", selector)], raw);
        }
        "tag" => {
            if let Some(tag) = rest.first() {
                let limit = rest.get(1).cloned().unwrap_or_else(|| "100".to_string());
                let _ = post_and_print(
                    &[("query", "get_taginfo"), ("tag", tag), ("limit", &limit)],
                    raw,
                );
            } else {
                eprintln!("tag requires <tag>");
            }
        }
        "cscb" => {
            let _ = post_and_print(&[("query", "get_cscb")], raw);
        }
        _ => print_usage(),
    }
}
