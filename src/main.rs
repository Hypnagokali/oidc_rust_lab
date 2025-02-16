use actix_web::{get, web::Query, App, HttpRequest, HttpResponse, HttpServer, Responder};
use openidconnect::{core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata}, reqwest::{self}, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl};



async fn authentication_flow() -> HttpResponse {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should have been built");   

    let meta_data = CoreProviderMetadata::discover_async(
        IssuerUrl::new("http://localhost:8786/realms/Test".to_owned()).unwrap(), 
        &http_client
    ).await
    .unwrap();

    println!("Metadata reveived ...");
    println!("{meta_data:?}");

    let oidc_client = CoreClient::from_provider_metadata(
        meta_data,
        ClientId::new("rustclient".to_owned()),
        // for this test I hardcoded the secret, don't do that at home or in production :)
        Some(ClientSecret::new("bl9WKkAk0iGwOF5me4qSatrClrTy1u8h".to_owned()))
    )
    .set_redirect_uri(RedirectUrl::new("http://localhost:5454/sso".to_owned()).unwrap());


    let (auth_url, state, nonce) = oidc_client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode, 
        || { CsrfToken::new("statevalue".to_owned())},
        || { Nonce::new("noncevalue".to_owned()) }
        // CsrfToken::new_random,
        // Nonce::new_random
    ).url();

    
    println!("REDIRECT TO: {}", auth_url);


    HttpResponse::MovedPermanently()
        .append_header(("Location", auth_url.to_string()))
        .finish()
}

#[get("/sso")]
async fn sso(req: HttpRequest) -> impl Responder {
    let query_params = req.query_string().split("&")
    .filter_map(|param| {
        let mut parts = param.split("=");
        Some((parts.next()?.to_owned(), parts.next().unwrap_or("").to_owned()))
    })
    .collect::<Vec<(String, String)>>();

    println!("(/sso) -> PARAMS");
    for p in query_params {
        println!("{} = {}", p.0, p.1);
    }

    HttpResponse::Ok().finish()
}

#[get("/")]
async fn profile(req: HttpRequest) -> impl Responder {
    // Step 1: check cookie
    if let Some(_token_cookieealm) = req.cookie("token") {
        // validate token
        
        HttpResponse::Ok()
            .content_type("text/html")
            .body("<h1>My Profile</h1>")
    } else {
        authentication_flow().await
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new().service(profile)
        .service(sso)
    })
    .bind(("127.0.0.1", 5454))?
    .run()
    .await
}