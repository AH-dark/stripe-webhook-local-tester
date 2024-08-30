use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::env;
use warp::Filter;

type HmacSha256 = Hmac<Sha256>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let secret = env::var("STRIPE_WEBHOOK_SECRET").unwrap().to_owned();

    let listener = warp::post()
        .and(warp::body::bytes())
        .and(warp::header::header::<String>("Stripe-Signature"))
        .map(move |body: bytes::Bytes, signature: String| {
            let body = String::from_utf8(body.to_vec()).unwrap();
            let timestamp = {
                let s = signature.split_once(",").unwrap().0;
                s.trim_start_matches("t=")
            }.parse::<i64>().unwrap();
            let except_signatures = {
                signature.split(",")
                    .filter(|s| s.starts_with("v1="))
                    .map(|s| s.trim_start_matches("v1="))
                    .collect::<Vec<&str>>()
            };

            let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
            mac.update(format!("{}.{}", timestamp, body).as_bytes());
            let result = mac.finalize().into_bytes();
            let signature = hex::encode(result);

            let is_valid = except_signatures.iter().any(|s| s == &signature);

            log::info!("is_valid: {}", is_valid);
            log::info!("except_signatures: {:?}, signature: {}, timestamp: {}", except_signatures, signature, timestamp);

            if is_valid {
                let target = std::env::current_dir()
                    .unwrap()
                    .join(format!("stripe_event_{}.json", timestamp));
                std::fs::write(target, body).unwrap();
            }

            warp::reply()
        });

    warp::serve(listener)
        .run(([127, 0, 0, 1], 8088))
        .await;

    Ok(())
}
