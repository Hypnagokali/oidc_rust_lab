use actix_web::{get, App, HttpRequest, HttpResponse, HttpServer, Responder};
use openidconnect::{core::CoreProviderMetadata, reqwest::{self}, IssuerUrl};



async fn authentication_flow() -> HttpResponse {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should have been build");   

    let meta_data = CoreProviderMetadata::discover_async(
        IssuerUrl::new("http://localhost:8786/realms/Test".to_owned()).unwrap(), 
        &http_client
    ).await
    .unwrap();

    println!("Metadata reveived ...");
    println!("{meta_data:?}");


    HttpResponse::Ok().finish()
}


#[get("/")]
async fn profile(req: HttpRequest) -> impl Responder {
    // Step 1: check cookie
    if let Some(_token_cookieealm) = req.cookie("token") {
        // validate token
        
        HttpResponse::Ok()
            .content_type("text/html")
            .body("<h1>Hello everyone - My Profile</h1>")
    } else {
        authentication_flow().await
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new().service(profile)
    })
    .bind(("127.0.0.1", 5454))?
    .run()
    .await
}